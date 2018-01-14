package scm

import (
	"testing"
	"github.com/rancher/pipeline/model"
)


// try to get accessToken
//
//func Test_oauth(t *testing.T) {
//	setting := &model.SCMSetting{HostName: ""}
//	geeManager := &GiteeManager{}
//	scmManager := geeManager.Config(setting)
//	scmManager.OAuth(
//	"http://localhost:8000",
//	"1a85557b062b90b573643f4f17de906bc141e1d65ff006db3a4f95aba1b390de",
//	"47ca639531fa521d541785ffaebfe237d183ac7ddcb5a86b7e8da8ccd794e587",
//	"5798c5b27d6a27b45912058600fbf56553f8c39bc7ebce6178b9bae8e6a4b546")
//}

const accessToken  = "fb63d3ae801d73d7364cd7b2cacf1d2a"

func Test_get_account(t *testing.T) {
	setting := &model.SCMSetting{HostName: ""}
	geeManager := &GiteeManager{}
	scmManager := geeManager.Config(setting)
	account, _ := scmManager.GetAccount(accessToken)

	if account.Name != "jamlee" {
		t.Errorf("account name not jamlee:", account.Name)
	}
}

func Test_get_repos(t *testing.T) {
	setting := &model.SCMSetting{HostName: ""}
	geeManager := &GiteeManager{}
	scmManager := geeManager.Config(setting)
	account, _ := scmManager.GetAccount(accessToken)
	repos, _ := scmManager.GetRepos(account)
	if len(repos) <= 0 {
		t.Errorf("account name not jamlee:", account.Name)
	}
}
