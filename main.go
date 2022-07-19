package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/data/binding"
	"fyne.io/fyne/v2/widget"
	"github.com/atotto/clipboard"
	"github.com/samber/lo"
	"golang.org/x/crypto/scrypt"
	"gopkg.in/ini.v1"
	"io"
	"io/fs"
	"io/ioutil"
	"net/http"
	"os/user"
	"path/filepath"
	"strings"
	"time"
)

type RemoteUpdateServerConfig struct {
	Port      string
	Password  string
	IsEnabled bool
}

type AutoSetRule struct {
	IsEnabled     bool
	AccountNumber string
	Profile       string
}

type AutoSetRules struct {
	Rules [10]AutoSetRule
}

type Clippy struct {
	viewModel                *ViewModel
	IsSendEnabled            bool                     `json:"isSendEnabled"`
	IsReceiveEnabled         bool                     `json:"isReceiveEnabled"`
	SendToTargets            []string                 `json:"sendToTargets"`
	RemoteUpdateServerConfig RemoteUpdateServerConfig `json:"remoteUpdateServerConfig"`
	AutoSetRules             AutoSetRules             `json:"autoSetRules"`
	textCredentialsData      string
	textSendToCsv            string
}

type ViewModel struct {
	ChkAutoSet  [10]binding.Bool
	ChkAutoSet1 binding.Bool
	ChkAutoSet2 binding.Bool

	TextAccountNumber  [10]binding.String
	TextAccountNumber1 binding.String
	TextAccountNumber2 binding.String

	TextProfile  [10]binding.String
	TextProfile1 binding.String
	TextProfile2 binding.String

	TextCredentialsData binding.ExternalString

	ChkAcceptRemoteUpdates   binding.Bool
	TextListenPort           binding.String
	TextRemoteUpdatePassword binding.String

	TextSendToCsv  binding.String
	ChkSendUpdates binding.Bool
}

func (c *Clippy) buildAutoSetRow(index int) *fyne.Container {
	c.viewModel.ChkAutoSet[index] = binding.BindBool(&c.AutoSetRules.Rules[index].IsEnabled)
	c.viewModel.TextAccountNumber[index] = binding.BindString(&c.AutoSetRules.Rules[index].AccountNumber)
	c.viewModel.TextProfile[index] = binding.BindString(&c.AutoSetRules.Rules[index].Profile)

	textAccountNumberEntry := widget.NewEntryWithData(c.viewModel.TextAccountNumber[index])
	textAccountNumberEntry.SetPlaceHolder("Account Number")
	textAccountNumberEntry.Wrapping = fyne.TextWrapOff

	textProfile := widget.NewEntryWithData(c.viewModel.TextProfile[index])
	textProfile.SetPlaceHolder("Target Profile")
	textProfile.Wrapping = fyne.TextWrapOff

	row := container.NewHBox(
		widget.NewCheckWithData("Auto set account number", c.viewModel.ChkAutoSet[index]),
		textAccountNumberEntry,
		widget.NewLabel("to profile"),
		textProfile,
	)

	return row
}

func (c *Clippy) buildAutoSetTab() *fyne.Container {
	/*
		c.viewModel.ChkAutoSet1 = binding.BindBool(&c.AutoSetRules.Rules[0].IsEnabled)
		c.viewModel.ChkAutoSet2 = binding.BindBool(&c.AutoSetRules.Rules[1].IsEnabled)

		c.viewModel.TextAccountNumber1 = binding.BindString(&c.AutoSetRules.Rules[0].AccountNumber)
		c.viewModel.TextAccountNumber2 = binding.BindString(&c.AutoSetRules.Rules[1].AccountNumber)

		c.viewModel.TextProfile1 = binding.BindString(&c.AutoSetRules.Rules[0].Profile)
		c.viewModel.TextProfile2 = binding.BindString(&c.AutoSetRules.Rules[1].Profile)
	*/

	c.viewModel.TextCredentialsData = binding.BindString(&c.textCredentialsData)

	/*
		textAccountNumber1Entry := widget.NewEntryWithData(c.viewModel.TextAccountNumber1)
		textAccountNumber1Entry.SetPlaceHolder("Account Number")
		textAccountNumber1Entry.Wrapping = fyne.TextWrapOff

		textAccountNumber2Entry := widget.NewEntryWithData(c.viewModel.TextAccountNumber2)
		textAccountNumber2Entry.SetPlaceHolder("Account Number")
		textAccountNumber2Entry.Wrapping = fyne.TextWrapOff

		textProfile1 := widget.NewEntryWithData(c.viewModel.TextProfile1)
		textProfile1.SetPlaceHolder("Target Profile")
		textProfile1.Wrapping = fyne.TextWrapOff

		textProfile2 := widget.NewEntryWithData(c.viewModel.TextProfile2)
		textProfile2.SetPlaceHolder("Target Profile")
		textProfile2.Wrapping = fyne.TextWrapOff
	*/

	textDetectedCredentialsMLE := widget.NewMultiLineEntry()
	textDetectedCredentialsMLE.SetMinRowsVisible(8)
	textDetectedCredentialsMLE.Bind(c.viewModel.TextCredentialsData)

	return container.NewVBox(
		widget.NewLabel("Detected Credentials"),
		textDetectedCredentialsMLE,
		c.buildAutoSetRow(0),
		c.buildAutoSetRow(1),
		c.buildAutoSetRow(2),
		c.buildAutoSetRow(3),
		/*widget.NewButton("Click", func() {
			s, _ := json.Marshal(c)

			fmt.Printf("Tapped, data: %s", s)

			chk1, _ := c.viewModel.ChkAutoSet1.Get()
			fmt.Printf("data.ChkAutoSet1.Get(): %t\n", chk1)
		}),*/
	)
}

func (c *Clippy) buildReceiveTab() *fyne.Container {
	c.viewModel.ChkAcceptRemoteUpdates = binding.BindBool(&c.RemoteUpdateServerConfig.IsEnabled)
	c.viewModel.TextListenPort = binding.BindString(&c.RemoteUpdateServerConfig.Port)
	c.viewModel.TextRemoteUpdatePassword = binding.BindString(&c.RemoteUpdateServerConfig.Password)

	entryPort := widget.NewEntryWithData(c.viewModel.TextListenPort)
	entryPort.SetPlaceHolder("Port #")
	entryPort.Wrapping = fyne.TextWrapOff

	entryPassword := widget.NewEntryWithData(c.viewModel.TextRemoteUpdatePassword)
	entryPassword.Password = true
	entryPassword.Wrapping = fyne.TextWrapOff

	chkIsEnabled1 := widget.NewCheckWithData("Accept Remote Updates", c.viewModel.ChkAcceptRemoteUpdates)

	row1 := container.NewVBox(
		chkIsEnabled1,
		widget.NewLabel("Password for remote updates."),
		entryPassword,
		widget.NewLabel("Listening Port for updates."),
		entryPort,
	)

	tab := container.NewVBox(
		row1,
	)

	tab.Resize(fyne.NewSize(400, 300))

	return tab
}

func (c *Clippy) buildSendTab() *fyne.Container {
	c.viewModel.TextSendToCsv = binding.BindString(&c.textSendToCsv)
	c.viewModel.ChkSendUpdates = binding.BindBool(&c.IsSendEnabled)

	remoteIpsEntry := widget.NewMultiLineEntry()
	remoteIpsEntry.SetPlaceHolder("1.2.3.4:8787,5.6.7.8:8787")
	remoteIpsEntry.Bind(c.viewModel.TextSendToCsv)
	remoteIpsEntry.OnChanged = func(value string) {
		c.SendToTargets = strings.Split(value, ",")
	}

	desc := widget.NewLabel("Configure other machines to send AWS credentials to. These remote machines must have Clippy running and must have Receive Updates configured.")
	desc.Wrapping = fyne.TextWrapWord

	tab := container.NewVBox(
		desc,
		widget.NewCheckWithData("Send Updates to Remote Machines", c.viewModel.ChkSendUpdates),
		widget.NewLabelWithStyle("Remote Machines (Comma Separated IP:Port)",
			fyne.TextAlignLeading, fyne.TextStyle{
				Bold:      false,
				Italic:    false,
				Monospace: false,
				Symbol:    false,
				TabWidth:  0,
			}),
		remoteIpsEntry,
	)

	return tab
}

func (c *Clippy) initDefaultConfig() {
	c.AutoSetRules = AutoSetRules{Rules: [10]AutoSetRule{
		{
			IsEnabled:     false,
			AccountNumber: "",
			Profile:       "",
		},
		{
			IsEnabled:     false,
			AccountNumber: "",
			Profile:       "",
		},
	}}

	c.RemoteUpdateServerConfig = RemoteUpdateServerConfig{
		Port:      "4678",
		Password:  "",
		IsEnabled: false,
	}
}

func (c *Clippy) readConfig(path string) {
	fileBytes, _ := ioutil.ReadFile(path)

	if len(fileBytes) > 0 {
		err := json.Unmarshal(fileBytes, c)

		if err != nil {
			fmt.Printf("Error: %s\n", err.Error())
		}
	} else {
		c.initDefaultConfig()
	}
}

func (c *Clippy) saveConfig(path string) {
	configBytes, _ := json.Marshal(c)

	ioutil.WriteFile(path, configBytes, fs.ModePerm)
}

func (c *Clippy) setProfile(awsCredentialsSection *ini.Section, profileTarget string) {
	// Load existing aws credentials file.
	// find existing profile target or create it
	usr, _ := user.Current()
	path := filepath.Join(usr.HomeDir, ".aws/credentials")
	existingCreds, _ := ini.Load(path)

	var targetSection *ini.Section

	if existingCreds.HasSection(profileTarget) == false {
		targetSection, _ = existingCreds.NewSection(profileTarget)
	} else {
		targetSection, _ = existingCreds.GetSection(profileTarget)
	}

	for _, key := range awsCredentialsSection.Keys() {
		targetSection.Key(key.Name()).SetValue(key.Value())
	}

	existingCreds.SaveTo(path)
}

func (c *Clippy) handleCredentialsSet(awsCredentials string, rules AutoSetRules) {
	iniSection, _ := ini.Load([]byte(awsCredentials))
	sections := iniSection.Sections()

	c.sendRemoteUpdates(awsCredentials)

	section, ok := lo.Find[*ini.Section](sections, func(s *ini.Section) bool {
		if strings.Contains(s.Name(), "_") {
			return true
		} else {
			return false
		}
	})

	if ok != true {
		return
	}

	credProfileName := section.Name()

	// get the text in [] (profile name)
	// credProfileName := awsCredentials[1:strings.IndexByte(awsCredentials, ']')]

	for _, rule := range rules.Rules {
		if strings.Contains(credProfileName, rule.AccountNumber) && rule.IsEnabled {
			c.setProfile(section, rule.Profile)
			fyne.CurrentApp().SendNotification(&fyne.Notification{
				Title:   "Clippy",
				Content: fmt.Sprintf("Profile '%s' updated.", rule.Profile),
			})
			break
		}
	}
}

func (c *Clippy) sendRemoteUpdates(awsCredentials string) {
	if c.IsSendEnabled == false {
		fmt.Printf("Skipping send updates. Setting is false.")
		return
	}

	encrypted, _ := c.Encrypt([]byte(c.RemoteUpdateServerConfig.Password), []byte(awsCredentials))

	encoded := base64.StdEncoding.EncodeToString(encrypted)

	client := &http.Client{}

	for _, target := range c.SendToTargets {
		targetUrl := fmt.Sprintf("http://%s/set", target)

		req, err := http.NewRequest("POST", targetUrl, bytes.NewReader([]byte(encoded)))

		if err != nil {
			fmt.Printf("Failed creating http request: %s\n", err.Error())
		}

		req.Header.Add("Authorization", c.RemoteUpdateServerConfig.Password)
		resp, err := client.Do(req)

		if err != nil {
			fmt.Printf("Error posting: %s\n", err.Error())
		}

		fmt.Printf("response: %+v\n", resp)
	}
}

func (c *Clippy) handleHttpRequest(w http.ResponseWriter, r *http.Request) {
	fmt.Printf("got / request\n%+v\n", r)
	io.WriteString(w, "ok\n")
	authHeader := r.Header.Get("authorization")
	if authHeader == c.RemoteUpdateServerConfig.Password {
		fmt.Println("Auth accepted.")
	} else {
		fmt.Printf("Auth failed: %s\n", authHeader)
	}

	body, err := ioutil.ReadAll(r.Body)

	if err != nil {
		fmt.Printf("Error getting body from post: %s\n", err.Error())
		return
	} else {
		fmt.Printf("Body: %s\n", body)
	}

	// convert body to encrypted bytes
	encryptedBytes, err := base64.StdEncoding.DecodeString(string(body))

	if err != nil {
		fmt.Printf("Failed decoding base64 string: %s\n", err.Error())
	}

	decryptedBytes, _ := c.Decrypt([]byte(c.RemoteUpdateServerConfig.Password), encryptedBytes)

	if err != nil {
		fmt.Printf("Failed decrypting payload: %s\n", err.Error())
	}

	fmt.Printf("decrypted bytes: %s\n", decryptedBytes)

	// now set the text

	c.textCredentialsData = string(decryptedBytes)

	c.handleCredentialsSet(string(decryptedBytes), c.AutoSetRules)
}

func (c *Clippy) startHttpServer() {
	http.HandleFunc("/set", c.handleHttpRequest)
	http.ListenAndServe(fmt.Sprintf(":%s", c.RemoteUpdateServerConfig.Port), nil)
}

func (c *Clippy) Encrypt(key, data []byte) ([]byte, error) {
	key, salt, err := c.DeriveKey(key, nil)
	if err != nil {
		return nil, err
	}

	blockCipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(blockCipher)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return nil, err
	}

	ciphertext := gcm.Seal(nonce, nonce, data, nil)

	ciphertext = append(ciphertext, salt...)

	return ciphertext, nil
}

func (c *Clippy) Decrypt(key, data []byte) ([]byte, error) {
	salt, data := data[len(data)-32:], data[:len(data)-32]

	key, _, err := c.DeriveKey(key, salt)
	if err != nil {
		return nil, err
	}

	blockCipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(blockCipher)
	if err != nil {
		return nil, err
	}

	nonce, ciphertext := data[:gcm.NonceSize()], data[gcm.NonceSize():]

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

func (c *Clippy) DeriveKey(password, salt []byte) ([]byte, []byte, error) {
	if salt == nil {
		salt = make([]byte, 32)
		if _, err := rand.Read(salt); err != nil {
			return nil, nil, err
		}
	}

	key, err := scrypt.Key(password, salt, 1048576, 8, 1, 32)
	if err != nil {
		return nil, nil, err
	}

	return key, salt, nil
}

func (c *Clippy) monitorClipboard() {
	lastAwsKey := ""

	for {
		clipText, _ := clipboard.ReadAll()

		if strings.Contains(strings.ToLower(clipText), "aws_access_key_id") {
			if strings.ToLower(lastAwsKey) != strings.ToLower(clipText) {
				c.textCredentialsData = clipText
				err := c.viewModel.TextCredentialsData.Reload()

				if err != nil {
					fmt.Printf("Error reloading binding for TextCredentialsData: %s\n", err.Error())
				}

				lastAwsKey = clipText
				c.handleCredentialsSet(clipText, c.AutoSetRules)
			}
		}

		time.Sleep(250 * time.Millisecond)
	}
}

func main() {
	clippy := Clippy{}
	usr, _ := user.Current()
	configPath := filepath.Join(usr.HomeDir, ".clippy.json")

	clippy.readConfig(configPath)
	clippy.viewModel = &ViewModel{}

	myApp := app.New()
	w := myApp.NewWindow("Clippy")
	w.Resize(fyne.NewSize(400, 480))

	autoSetTab := clippy.buildAutoSetTab()
	receiveTab := clippy.buildReceiveTab()
	sendTab := clippy.buildSendTab()

	appTabs := container.NewAppTabs(
		container.NewTabItem("Auto Set", autoSetTab),
		container.NewTabItem("Receive", receiveTab),
		container.NewTabItem("Send", sendTab),
	)

	w.SetContent(container.NewVBox(
		appTabs,
	))

	// appTabs.SelectIndex(1)
	go clippy.monitorClipboard()

	if clippy.RemoteUpdateServerConfig.IsEnabled {
		go clippy.startHttpServer()
	}
	w.ShowAndRun()

	clippy.saveConfig(configPath)
}
