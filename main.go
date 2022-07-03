package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/atotto/clipboard"
	"github.com/bep/debounce"
	"github.com/samber/lo"
	"github.com/therecipe/qt/core"
	"github.com/therecipe/qt/gui"
	"golang.org/x/crypto/scrypt"
	"gopkg.in/ini.v1"
	"io"
	"io/fs"
	"io/ioutil"
	"net/http"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/therecipe/qt/widgets"
)

// examples: https://golang.hotexamples.com/examples/github.com.therecipe.qt.widgets/-/NewQApplication/golang-newqapplication-function-examples.html
type SendUpdatesToInputs struct {
	ChkIsEnabled *widgets.QCheckBox
	InputRemotes *widgets.QLineEdit
}

type RemoteUpdateServerInputs struct {
	ChkIsEnabled *widgets.QCheckBox
	InputPort    *widgets.QLineEdit
	InputPass    *widgets.QLineEdit
}

type AutoSetRulesInputs struct {
	ChkRule1      *widgets.QCheckBox
	InputAcct1    *widgets.QLineEdit
	InputProfile1 *widgets.QLineEdit

	ChkRule2      *widgets.QCheckBox
	InputAcct2    *widgets.QLineEdit
	InputProfile2 *widgets.QLineEdit
}

type AutoSetRule struct {
	IsEnabled     bool
	AccountNumber string
	Profile       string
}

type AutoSetRules struct {
	Rules []AutoSetRule
}

type RemoteUpdateServerConfig struct {
	Port      int
	Password  string
	IsEnabled bool
}

type Config struct {
	AutoSetRules             AutoSetRules             `json:"autoSetRules"`
	SendToTargets            []string                 `json:"sendToTargets"`
	SendToTargetsEnabled     bool                     `json:"sendToTargetsEnabled"`
	RemoteUpdateServerConfig RemoteUpdateServerConfig `json:"remoteUpdateServerConfig"`
}

type Clippy struct {
	config         *Config
	updatePassword string
	serverPort     int
	keyInput       *widgets.QTextEdit
	autoSetRules   AutoSetRules
}

var debounced func(f func())
var remoteServerInputs RemoteUpdateServerInputs
var autoSetInputs AutoSetRulesInputs
var sendToInputs SendUpdatesToInputs

func (c *Clippy) readConfig(path string) *Config {
	fileBytes, _ := ioutil.ReadFile(path)

	config := &Config{}

	err := json.Unmarshal(fileBytes, config)

	if err != nil {
		fmt.Printf("Error: %s\n", err.Error())
	}
	return config
}

func (c *Clippy) saveConfig(path string, config *Config) {
	configBytes, _ := json.Marshal(config)

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
			break
		}
	}
}

func (c *Clippy) sendRemoteUpdates(awsCredentials string) {
	if c.config.SendToTargetsEnabled == false {
		fmt.Printf("Skipping send updates. Setting is false.")
		return
	}

	encrypted, _ := c.Encrypt([]byte(c.updatePassword), []byte(awsCredentials))

	encoded := base64.StdEncoding.EncodeToString(encrypted)

	client := &http.Client{}

	for _, target := range c.config.SendToTargets {
		targetUrl := fmt.Sprintf("http://%s/set", target)

		req, err := http.NewRequest("POST", targetUrl, bytes.NewReader([]byte(encoded)))

		if err != nil {
			fmt.Printf("Failed creating http request: %s\n", err.Error())
		}

		req.Header.Add("Authorization", c.updatePassword)
		resp, err := client.Do(req)

		if err != nil {
			fmt.Printf("Error posting: %s\n", err.Error())
		}

		fmt.Printf("response: %+v\n", resp)
	}
}

func (c *Clippy) getAutoSetRules(inputs *AutoSetRulesInputs) AutoSetRules {
	rules := AutoSetRules{
		Rules: []AutoSetRule{
			{
				IsEnabled:     inputs.ChkRule1.IsChecked(),
				AccountNumber: inputs.InputAcct1.Text(),
				Profile:       inputs.InputProfile1.Text(),
			},
			{
				IsEnabled:     inputs.ChkRule2.IsChecked(),
				AccountNumber: inputs.InputAcct2.Text(),
				Profile:       inputs.InputProfile2.Text(),
			},
		},
	}

	return rules
}

func (c *Clippy) monitorClipboard(input *widgets.QTextEdit, inputs *AutoSetRulesInputs) {
	lastAwsKey := ""

	for {
		clipText, _ := clipboard.ReadAll()

		if strings.Contains(strings.ToLower(clipText), "aws_access_key_id") {
			if strings.ToLower(lastAwsKey) != strings.ToLower(clipText) {
				input.SetPlainTextDefault(clipText)
				lastAwsKey = clipText
				rules := c.getAutoSetRules(inputs)
				c.handleCredentialsSet(clipText, rules)
			}
		}

		time.Sleep(250 * time.Millisecond)
	}
}

func (c *Clippy) addAutoSetInputsRow(grid *widgets.QGridLayout, row int) (*widgets.QCheckBox, *widgets.QLineEdit, *widgets.QLineEdit) {
	checkbox := widgets.NewQCheckBox2("Auto set account number", nil)
	grid.AddWidget3(checkbox, row, 0, 1, 1, core.Qt__AlignCenter)

	inputAccountRule := widgets.NewQLineEdit2("", nil)
	grid.AddWidget3(inputAccountRule, row, 1, 1, 1, core.Qt__AlignCenter)

	label := widgets.NewQLabel2("to profile", nil, 0)
	grid.AddWidget3(label, row, 2, 1, 1, core.Qt__AlignCenter)

	inputProfileRule := widgets.NewQLineEdit2("", nil)

	grid.AddWidget3(inputProfileRule, row, 3, 1, 1, core.Qt__AlignCenter)

	return checkbox, inputAccountRule, inputProfileRule
}

func (c *Clippy) addAutoSetGroup() (*widgets.QGroupBox, *AutoSetRulesInputs) {
	groupbox := widgets.NewQGroupBox2("Auto Set Rules", nil)
	gridLayout := widgets.NewQGridLayout2()
	groupbox.SetLayout(gridLayout)
	groupbox.SetMinimumHeight(80)

	chkRule1, liAccountRule1, liProfileRule1 := c.addAutoSetInputsRow(gridLayout, 0)
	chkRule2, liAccountRule2, liProfileRule2 := c.addAutoSetInputsRow(gridLayout, 1)

	return groupbox, &AutoSetRulesInputs{
		ChkRule1:      chkRule1,
		InputAcct1:    liAccountRule1,
		InputProfile1: liProfileRule1,
		ChkRule2:      chkRule2,
		InputAcct2:    liAccountRule2,
		InputProfile2: liProfileRule2,
	}
}

func (c *Clippy) addRemoteUpdateServerGroup() (*widgets.QGroupBox, *RemoteUpdateServerInputs) {
	groupbox := widgets.NewQGroupBox2("Remote Update Server", nil)
	gridLayout := widgets.NewQGridLayout2()
	groupbox.SetLayout(gridLayout)
	groupbox.SetMinimumHeight(80)

	labelPort := widgets.NewQLabel2("Port", nil, 0)
	gridLayout.AddWidget3(labelPort, 0, 1, 1, 1, core.Qt__AlignLeft)

	labelPass := widgets.NewQLabel2("Password", nil, 0)
	gridLayout.AddWidget3(labelPass, 0, 2, 1, 1, core.Qt__AlignLeft)

	checkbox := widgets.NewQCheckBox2("Accept Updates", nil)
	gridLayout.AddWidget3(checkbox, 1, 0, 1, 1, core.Qt__AlignLeft)

	inputPort := widgets.NewQLineEdit2("", nil)
	gridLayout.AddWidget3(inputPort, 1, 1, 1, 1, core.Qt__AlignLeft)

	inputPass := widgets.NewQLineEdit2("", nil)
	inputPass.SetEchoMode(widgets.QLineEdit__Password)
	gridLayout.AddWidget3(inputPass, 1, 2, 1, 1, core.Qt__AlignLeft)

	return groupbox, &RemoteUpdateServerInputs{
		ChkIsEnabled: checkbox,
		InputPort:    inputPort,
		InputPass:    inputPass,
	}
}

func dataChangedEvent(event any) {
	fmt.Printf("event: %+v\n", event)

}

func (c *Clippy) addSendToSettings() (*widgets.QGroupBox, *SendUpdatesToInputs) {
	groupbox := widgets.NewQGroupBox2("Sent Updates To", nil)
	gridLayout := widgets.NewQGridLayout2()
	groupbox.SetLayout(gridLayout)
	groupbox.SetMinimumHeight(80)

	checkbox := widgets.NewQCheckBox2("Send Updates", nil)
	gridLayout.AddWidget3(checkbox, 1, 0, 1, 1, core.Qt__AlignLeft)

	labelMachines := widgets.NewQLabel2("Remote Machines (Comma Separated List)", nil, 0)
	gridLayout.AddWidget3(labelMachines, 0, 1, 1, 2, core.Qt__AlignLeft)

	inputRemoteMachines := widgets.NewQLineEdit2("", nil)
	inputRemoteMachines.SetMinimumWidth(300)
	gridLayout.AddWidget3(inputRemoteMachines, 1, 1, 1, 2, core.Qt__AlignLeft)

	return groupbox, &SendUpdatesToInputs{
		ChkIsEnabled: checkbox,
		InputRemotes: inputRemoteMachines,
	}
}

func (c *Clippy) setInputsFromConfig(config *Config,
	autoSetInputs *AutoSetRulesInputs,
	remoteServerInputs *RemoteUpdateServerInputs,
	sendToInputs *SendUpdatesToInputs) {
	if config == nil {
		return
	}

	autoSetInputs.ChkRule1.SetChecked(config.AutoSetRules.Rules[0].IsEnabled)
	autoSetInputs.ChkRule2.SetChecked(config.AutoSetRules.Rules[1].IsEnabled)

	autoSetInputs.InputProfile1.SetText(config.AutoSetRules.Rules[0].Profile)
	autoSetInputs.InputProfile2.SetText(config.AutoSetRules.Rules[1].Profile)

	autoSetInputs.InputAcct1.SetText(config.AutoSetRules.Rules[0].AccountNumber)
	autoSetInputs.InputAcct2.SetText(config.AutoSetRules.Rules[1].AccountNumber)

	remoteServerInputs.InputPort.SetText(strconv.FormatInt(int64(config.RemoteUpdateServerConfig.Port), 10))
	remoteServerInputs.InputPass.SetText(config.RemoteUpdateServerConfig.Password)
	remoteServerInputs.ChkIsEnabled.SetChecked(config.RemoteUpdateServerConfig.IsEnabled)

	if config.SendToTargets != nil && len(config.SendToTargets) > 0 {
		sendToInputs.InputRemotes.SetText(strings.Join(config.SendToTargets, ","))
	}

	sendToInputs.ChkIsEnabled.SetChecked(config.SendToTargetsEnabled)
}

func (c *Clippy) setConfigFromInputs(config *Config,
	autoSetInputs *AutoSetRulesInputs,
	remoteServerInputs *RemoteUpdateServerInputs,
	sendToInputs *SendUpdatesToInputs) *Config {
	if config == nil {
		config = &Config{
			AutoSetRules:  AutoSetRules{},
			SendToTargets: nil,
		}
	}

	config.AutoSetRules.Rules = []AutoSetRule{
		{
			IsEnabled:     autoSetInputs.ChkRule1.IsChecked(),
			AccountNumber: autoSetInputs.InputAcct1.Text(),
			Profile:       autoSetInputs.InputProfile1.Text(),
		},
		{
			IsEnabled:     autoSetInputs.ChkRule2.IsChecked(),
			AccountNumber: autoSetInputs.InputAcct2.Text(),
			Profile:       autoSetInputs.InputProfile2.Text(),
		},
	}

	port := 4335
	port, _ = strconv.Atoi(remoteServerInputs.InputPort.Text())

	config.RemoteUpdateServerConfig = RemoteUpdateServerConfig{
		Port:      port,
		Password:  remoteServerInputs.InputPass.Text(),
		IsEnabled: remoteServerInputs.ChkIsEnabled.IsChecked(),
	}

	config.SendToTargetsEnabled = sendToInputs.ChkIsEnabled.IsChecked()
	config.SendToTargets = strings.Split(sendToInputs.InputRemotes.Text(), ",")

	return config
}

func (c *Clippy) handleHttpRequest(w http.ResponseWriter, r *http.Request) {
	fmt.Printf("got / request\n%+v\n", r)
	io.WriteString(w, "ok\n")
	authHeader := r.Header.Get("authorization")
	if authHeader == c.updatePassword {
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

	decryptedBytes, _ := c.Decrypt([]byte(c.updatePassword), encryptedBytes)

	if err != nil {
		fmt.Printf("Failed decrypting payload: %s\n", err.Error())
	}

	fmt.Printf("decrypted bytes: %s\n", decryptedBytes)

	// now set the text

	c.keyInput.SetPlainTextDefault(string(decryptedBytes))

	c.handleCredentialsSet(string(decryptedBytes), c.autoSetRules)
}

func (c *Clippy) startHttpServer() {
	http.HandleFunc("/set", c.handleHttpRequest)
	http.ListenAndServe(fmt.Sprintf(":%d", c.serverPort), nil)
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

func main() {
	usr, _ := user.Current()
	configPath := filepath.Join(usr.HomeDir, ".clippy.json")
	clippy := Clippy{}

	clippy.config = clippy.readConfig(configPath)

	if clippy.config != nil {
		clippy.updatePassword = clippy.config.RemoteUpdateServerConfig.Password
		clippy.serverPort = clippy.config.RemoteUpdateServerConfig.Port
	}

	debounced = debounce.New(250 * time.Millisecond)

	// needs to be called once before you can start using the QWidgets
	app := widgets.NewQApplication(len(os.Args), os.Args)

	// create a window
	// with a minimum size of 250*200
	// and sets the title to "Hello Widgets Example"
	window := widgets.NewQMainWindow(nil, 0)

	window.SetMinimumSize2(500, 200)
	window.SetWindowTitle("Clippy")

	widget := widgets.NewQWidget(nil, 0)
	widget.SetLayout(widgets.NewQVBoxLayout())

	window.SetCentralWidget(widget)

	groupbox, autoSetInputs := clippy.addAutoSetGroup()
	widget.Layout().AddWidget(groupbox)

	groupboxRemoteServer, remoteServerInputs := clippy.addRemoteUpdateServerGroup()
	widget.Layout().AddWidget(groupboxRemoteServer)

	groupboxSendTo, sendToInputs := clippy.addSendToSettings()
	widget.Layout().AddWidget(groupboxSendTo)

	input := widgets.NewQTextEdit(nil)
	input.SetPlaceholderText("AWS Keys will appear here..")
	clippy.keyInput = input

	widget.Layout().AddWidget(input)

	// create a button
	// connect the clicked signal
	// and add it to the central widgets layout
	//button := widgets.NewQPushButton2("and click me!", nil)
	//button.ConnectClicked(func(bool) {
	//	widgets.QMessageBox_Information(nil, "OK", input.ToPlainText(), widgets.QMessageBox__Ok, widgets.QMessageBox__Ok)
	//})
	//widget.Layout().AddWidget(button)

	// make the window visible
	window.Show()

	clippy.setInputsFromConfig(clippy.config, autoSetInputs, remoteServerInputs, sendToInputs)

	clippy.autoSetRules = clippy.getAutoSetRules(autoSetInputs)

	go clippy.monitorClipboard(input, autoSetInputs)

	if clippy.config.RemoteUpdateServerConfig.IsEnabled {
		go clippy.startHttpServer()
	}

	// save the config when closing the app
	window.ConnectCloseEvent(func(event *gui.QCloseEvent) {
		fmt.Printf("Closing window.")
		clippy.config = clippy.setConfigFromInputs(clippy.config, autoSetInputs, remoteServerInputs, sendToInputs)
		clippy.saveConfig(configPath, clippy.config)
	})

	// start the main Qt event loop
	// and block until app.Exit() is called
	// or the window is closed by the user
	app.Exec()
}
