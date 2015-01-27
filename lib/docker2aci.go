// Package docker2aci plements a simple library for converting docker images to
// App Container Images (ACIs).
package docker2aci

import (
	"archive/tar"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/appc/spec/schema"
	"github.com/appc/spec/schema/types"
	"github.com/docker/docker/runconfig"
)

type DockerImageData struct {
	ID            string            `json:"id"`
	Parent        string            `json:"parent,omitempty"`
	Comment       string            `json:"comment,omitempty"`
	Created       time.Time         `json:"created"`
	Container     string            `json:"container,omitempty"`
	DockerVersion string            `json:"docker_version,omitempty"`
	Author        string            `json:"author,omitempty"`
	Config        *runconfig.Config `json:"config,omitempty"`
	Architecture  string            `json:"architecture,omitempty"`
	OS            string            `json:"os,omitempty"`
	Checksum      string            `json:"checksum"`
}

type RepoData struct {
	Tokens    []string
	Endpoints []string
	Cookie    []string
}

type DockerURL struct {
	IndexURL  string
	ImageName string
	Tag       string
}

type ACIApp struct {
	ACILayers     []string
	PathWhitelist []string
}

const (
	defaultIndex  = "index.docker.io"
	defaultTag    = "latest"
	schemaVersion = "0.1.1"
)

/*
	Convert generates ACI images from docker registry URLs.
	It takes as input a dockerURL of the form:

		{docker registry URL}/{image name}:{tag}
	
	It then gets all the layers of the requested image, converts each of them
	to ACI and places the resulting files in outputDir.
	It returns the list of generated ACI paths.
*/
func Convert(dockerURL string, outputDir string) ([]string, error) {
	parsedURL := parseDockerURL(dockerURL)

	repoData, err := getRepoData(parsedURL.IndexURL, parsedURL.ImageName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error getting image data: %v\n", err)
		return nil, err
	}

	// TODO(iaguis) check more endpoints
	appImageID, err := getImageIDFromTag(repoData.Endpoints[0], parsedURL.ImageName, parsedURL.Tag, repoData)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error getting ImageID from tag %s: %v\n", parsedURL.Tag, err)
		return nil, err
	}

	ancestry, err := getAncestry(appImageID, repoData.Endpoints[0], repoData)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error getting ancestry: %v\n", err)
		return nil, err
	}

	aciACC := new(ACIApp)
	for _, layerID := range ancestry {
		aciACC, err = buildACI(layerID, repoData, parsedURL, aciACC, outputDir)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error building layer: %v\n", err)
			return nil, err
		}
	}

	return aciACC.ACILayers, nil
}

func parseDockerURL(arg string) *DockerURL {
	indexURL := defaultIndex
	tag := defaultTag

	argParts := strings.SplitN(arg, "/", 2)
	var appString string
	if len(argParts) > 1 {
		if strings.Index(argParts[0], ".") != -1 {
			indexURL = argParts[0]
			appString = argParts[1]
		} else {
			appString = strings.Join(argParts, "/")
		}
	} else {
		appString = argParts[0]
	}

	imageName := appString
	appParts := strings.Split(appString, ":")

	if len(appParts) > 1 {
		tag = appParts[len(appParts)-1]
		imageNameParts := appParts[0 : len(appParts)-1]
		imageName = strings.Join(imageNameParts, ":")
	}

	return &DockerURL{
		IndexURL:  indexURL,
		ImageName: imageName,
		Tag:       tag,
	}
}

func getRepoData(indexURL string, remote string) (*RepoData, error) {
	client := &http.Client{}
	repositoryURL := fmt.Sprintf("%s/%s/v1/%s/%s/images", "https:/", indexURL, "repositories", remote)

	req, err := http.NewRequest("GET", repositoryURL, nil)
	if err != nil {
		return nil, err
	}

	// TODO(iaguis) add auth?
	req.Header.Set("X-Docker-Token", "true")

	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	if res.StatusCode != 200 {
		return nil, fmt.Errorf("HTTP code: %d, URL: %s", res.StatusCode, req.URL)
	}

	var tokens []string
	if res.Header.Get("X-Docker-Token") != "" {
		tokens = res.Header["X-Docker-Token"]
	}

	var cookies []string
	if res.Header.Get("Set-Cookie") != "" {
		cookies = res.Header["Set-Cookie"]
	}

	var endpoints []string
	if res.Header.Get("X-Docker-Endpoints") != "" {
		endpoints = makeEndpointsList(res.Header["X-Docker-Endpoints"])
	} else {
		// Assume same endpoint
		endpoints = append(endpoints, indexURL)
	}

	return &RepoData{
		Endpoints: endpoints,
		Tokens:    tokens,
		Cookie:    cookies,
	}, nil
}

func getImageIDFromTag(registry string, appName string, tag string, repoData *RepoData) (string, error) {
	client := &http.Client{}
	req, err := http.NewRequest("GET", registry+"repositories/"+appName+"/tags/"+tag, nil)
	if err != nil {
		return "", fmt.Errorf("Failed to get Image ID: %s, URL: %s", err, req.URL)
	}

	setAuthToken(req, repoData.Tokens)
	setCookie(req, repoData.Cookie)
	res, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("Failed to get Image ID: %s, URL: %s", err, req.URL)
	}
	defer res.Body.Close()

	if res.StatusCode != 200 {
		return "", fmt.Errorf("HTTP code: %d. URL: %s", res.StatusCode, req.URL)
	}

	jsonString, err := ioutil.ReadAll(res.Body)

	if err != nil {
		return "", err
	}

	var imageID string

	if err := json.Unmarshal(jsonString, &imageID); err != nil {
		return "", fmt.Errorf("Error unmarshaling: %v", err)
	}

	return imageID, nil
}

func getAncestry(imgID, registry string, repoData *RepoData) ([]string, error) {
	client := &http.Client{}
	req, err := http.NewRequest("GET", registry+"images/"+imgID+"/ancestry", nil)
	if err != nil {
		return nil, err
	}

	setAuthToken(req, repoData.Tokens)
	setCookie(req, repoData.Cookie)
	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	if res.StatusCode != 200 {
		return nil, fmt.Errorf("HTTP code: %d. URL: %s", res.StatusCode, req.URL)
	}

	var ancestry []string

	jsonString, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, fmt.Errorf("Failed to read downloaded json: %s (%s)", err, jsonString)
	}

	if err := json.Unmarshal(jsonString, &ancestry); err != nil {
		return nil, fmt.Errorf("Error unmarshaling: %v", err)
	}

	return ancestry, nil
}

func buildACI(layerID string, repoData *RepoData, dockerURL *DockerURL, acc *ACIApp, outputDir string) (*ACIApp, error) {
	tmpDir, err := ioutil.TempDir("", "docker2aci-")
	if err != nil {
		return nil, fmt.Errorf("Error creating dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	layerDest := tmpDir + "/layer"
	layerRootfs := layerDest + "/rootfs"
	err = os.MkdirAll(layerRootfs, 0700)
	if err != nil {
		return nil, fmt.Errorf("Error creating dir: %s", layerRootfs)
	}

	jsonString, size, err := getRemoteImageJSON(layerID, repoData.Endpoints[0], repoData)
	if err != nil {
		return nil, fmt.Errorf("Error getting image json: %v", err)
	}

	layerData := DockerImageData{}
	if err := json.Unmarshal(jsonString, &layerData); err != nil {
		return nil, fmt.Errorf("Error unmarshaling layer data: %v", err)
	}

	layer, err := getRemoteLayer(layerID, repoData.Endpoints[0], repoData, int64(size))
	if err != nil {
		return nil, fmt.Errorf("Error getting the remote layer: %v", err)
	}
	defer layer.Close()

	imageName := strings.Replace(dockerURL.ImageName, "/", "-", -1)
	aciPath := imageName + "-" + layerID
	if dockerURL.Tag != "" {
		aciPath += "-" + dockerURL.Tag
	}
	if layerData.OS != "" {
		aciPath += "-" + layerData.OS
		if layerData.Architecture != "" {
			aciPath += "-" + layerData.Architecture
		}
	}
	aciPath += ".aci"

	aciPath = path.Join(outputDir, aciPath)

	newPathWhitelist, err := writeACI(layer, layerData, dockerURL, acc.PathWhitelist, aciPath)
	if err != nil {
		return nil, fmt.Errorf("Error writing ACI: %v", err)
	}

	acc.ACILayers = append(acc.ACILayers, aciPath)
	acc.PathWhitelist = newPathWhitelist

	return acc, nil
}

func getRemoteImageJSON(imgID, registry string, repoData *RepoData) ([]byte, int, error) {
	client := &http.Client{}
	req, err := http.NewRequest("GET", registry+"images/"+imgID+"/json", nil)
	if err != nil {
		return nil, -1, err
	}
	setAuthToken(req, repoData.Tokens)
	setCookie(req, repoData.Cookie)
	res, err := client.Do(req)
	if err != nil {
		return nil, -1, err
	}
	defer res.Body.Close()

	if res.StatusCode != 200 {
		return nil, -1, fmt.Errorf("HTTP code: %d, URL: %s", res.StatusCode, req.URL)
	}

	imageSize := -1

	if hdr := res.Header.Get("X-Docker-Size"); hdr != "" {
		imageSize, err = strconv.Atoi(hdr)
		if err != nil {
			return nil, -1, err
		}
	}

	jsonBytes, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, -1, fmt.Errorf("Failed to read downloaded json: %v (%s)", err, jsonBytes)
	}

	return jsonBytes, imageSize, nil
}

func getRemoteLayer(imgID, registry string, repoData *RepoData, imgSize int64) (io.ReadCloser, error) {
	client := &http.Client{}
	req, err := http.NewRequest("GET", registry+"images/"+imgID+"/layer", nil)
	if err != nil {
		return nil, err
	}

	setAuthToken(req, repoData.Tokens)
	setCookie(req, repoData.Cookie)

	fmt.Printf("Downloading layer: %s\n", imgID)

	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	if res.StatusCode != 200 {
		res.Body.Close()
		return nil, fmt.Errorf("HTTP code: %d. URL: %s", res.StatusCode, req.URL)
	}

	return res.Body, nil
}

func generateManifest(layerData DockerImageData, dockerURL *DockerURL, pathWhitelist []string) (*schema.ImageManifest, error) {
	dockerConfig := layerData.Config
	genManifest := &schema.ImageManifest{}

	appURL := dockerURL.IndexURL + "/" + dockerURL.ImageName + "-" + layerData.ID
	name, err := types.NewACName(appURL)
	if err != nil {
		return nil, err
	}
	genManifest.Name = *name

	acVersion, _ := types.NewSemVer(schemaVersion)
	genManifest.ACVersion = *acVersion

	genManifest.ACKind = types.ACKind("ImageManifest")

	var labels types.Labels
	var parentLabels types.Labels

	layer, _ := types.NewACName("layer")
	labels = append(labels, types.Label{Name: *layer, Value: layerData.ID})

	tag := dockerURL.Tag
	version, _ := types.NewACName("version")
	labels = append(labels, types.Label{Name: *version, Value: tag})

	if layerData.OS != "" {
		os, _ := types.NewACName("os")
		labels = append(labels, types.Label{Name: *os, Value: layerData.OS})
		parentLabels = append(parentLabels, types.Label{Name: *os, Value: layerData.OS})

		if layerData.Architecture != "" {
			arch, _ := types.NewACName("arch")
			parentLabels = append(parentLabels, types.Label{Name: *arch, Value: layerData.Architecture})
		}
	}

	genManifest.Labels = labels

	if dockerConfig != nil {
		var exec types.Exec
		if len(dockerConfig.Cmd) > 0 {
			exec = types.Exec(dockerConfig.Cmd)
		} else if len(dockerConfig.Entrypoint) > 0 {
			exec = types.Exec(dockerConfig.Entrypoint)
		}
		if exec != nil {
			// TODO(iaguis) populate user and group
			user, group := parseDockerUser(dockerConfig.User)
			app := &types.App{Exec: exec, User: user, Group: group}
			genManifest.App = app
		}
	}

	if layerData.Parent != "" {
		var dependencies types.Dependencies
		parentAppNameString := dockerURL.IndexURL + "/" + dockerURL.ImageName + "-" + layerData.Parent

		parentAppName, err := types.NewACName(parentAppNameString)
		if err != nil {
			return nil, err
		}

		dependencies = append(dependencies, types.Dependency{App: *parentAppName, Labels: parentLabels})

		genManifest.Dependencies = dependencies
	}

	if len(pathWhitelist) > 0 {
		genManifest.PathWhitelist = pathWhitelist
	}

	return genManifest, nil
}

func parseDockerUser(dockerUser string) (string, string) {
	if dockerUser == "" {
		return "0", "0"
	}

	dockerUserParts := strings.Split(dockerUser, ":")

	if len(dockerUserParts) < 2 {
		return dockerUserParts[0], "0"
	}

	return dockerUserParts[0], dockerUserParts[1]
}

func in(list []string, el string) bool {
	for _, x := range list {
		if el == x {
			return true
		}
	}
	return false
}

func substractWhiteouts(pathWhitelist []string, whiteouts []string) []string {
	for i, whiteout := range whiteouts {
		if in(pathWhitelist, whiteout) {
			pathWhitelist = append(pathWhitelist[:i], pathWhitelist[i+1:]...)
		}
	}

	return pathWhitelist
}

func writeACI(layer io.Reader, layerData DockerImageData, dockerURL *DockerURL, curPathWhitelist []string, output string) ([]string, error) {
	reader, err := decompress(layer)
	if err != nil {
		return nil, err
	}

	tr := tar.NewReader(reader)

	aciFile, err := os.Create(output)
	if err != nil {
		return nil, fmt.Errorf("Error creating ACI file: %v", err)
	}
	defer aciFile.Close()

	trw := tar.NewWriter(aciFile)

	var whiteouts []string
	// Write files in rootfs/
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			// end of tar archive
			break
		}
		if err != nil {
			return nil, fmt.Errorf("Error reading layer tar entry: %v", err)
		}
		if hdr.Name == "./" {
			continue
		}
		absolutePath := "/" + hdr.Name

		// FIXME(iaguis) although unlikely, a file named like "/what.wh.ever should be legal
		if strings.Index(absolutePath, ".wh.") != -1 {
			whiteouts = append(whiteouts, strings.Replace(absolutePath, ".wh.", "", -1))
			continue
		}
		hdr.Name = "rootfs/" + hdr.Name
		if hdr.Typeflag == tar.TypeLink {
			hdr.Linkname = "rootfs/" + hdr.Linkname
		}
		if err := trw.WriteHeader(hdr); err != nil {
			return nil, fmt.Errorf("Error writing header: %v", err)
		}
		if _, err := io.Copy(trw, tr); err != nil {
			return nil, fmt.Errorf("Error copying file into the tar out: %v", err)
		}
		if !in(curPathWhitelist, absolutePath) {
			curPathWhitelist = append(curPathWhitelist, absolutePath)
		}
	}

	pathWhitelist := substractWhiteouts(curPathWhitelist, whiteouts)

	manifest, err := generateManifest(layerData, dockerURL, pathWhitelist)
	if err != nil {
		return nil, fmt.Errorf("Error generating the manifest: %v", err)
	}

	manifestBytes, err := json.Marshal(manifest)
	if err != nil {
		return nil, err
	}

	// Write manifest
	hdr := &tar.Header{
		Name: "manifest",
		Mode: 0600,
		Size: int64(len(manifestBytes)),
	}
	if err := trw.WriteHeader(hdr); err != nil {
		return nil, err
	}
	if _, err := trw.Write(manifestBytes); err != nil {
		return nil, err
	}

	if err := trw.Close(); err != nil {
		return nil, fmt.Errorf("Error closing ACI file: %v", err)
	}

	return pathWhitelist, nil
}

func setAuthToken(req *http.Request, token []string) {
	if req.Header.Get("Authorization") == "" {
		req.Header.Set("Authorization", "Token "+strings.Join(token, ","))
	}
}

func setCookie(req *http.Request, cookie []string) {
	if req.Header.Get("Cookie") == "" {
		req.Header.Set("Cookie", strings.Join(cookie, ""))
	}
}
