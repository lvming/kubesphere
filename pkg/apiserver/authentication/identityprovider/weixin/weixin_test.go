/*
 * Please refer to the LICENSE file in the root directory of the project.
 * https://github.com/kubesphere/kubesphere/blob/master/LICENSE
 */

package weixin

import (
	"encoding/json"
	"fmt"
	"kubesphere.io/kubesphere/pkg/server/options"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/onsi/gomega/gexec"
	"golang.org/x/oauth2"
	"gopkg.in/yaml.v3"
	"kubesphere.io/kubesphere/pkg/apiserver/authentication/identityprovider"
)

var weixinServer *httptest.Server

func TestWeixin(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Weixin Identity Provider Suite")
}

var _ = BeforeSuite(func() {
	weixinServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var data map[string]interface{}
		switch r.URL.Path {
		case "/sns/oauth2/access_token":
			data = map[string]interface{}{
				"access_token":  "access_token",
				"expires_in":    uint64(3600),
				"refresh_token": "refresh_token",
				"openid":        "openid",
				"scope":         "scope",
				"unionid":       "unionid",
			}
			break
		case "/sns/userinfo":
			data = map[string]interface{}{
				"unionid":    "unionid",
				"openid":     "openid",
				"nickname":   "nickname",
				"headimgurl": "headimgurl",
			}
			break
		default:
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("not implemented"))
			return
		}

		w.Header().Add("Content-Type", "application/json")
		json.NewEncoder(w).Encode(data)
	}))
})

var _ = AfterSuite(func() {
	By("tearing down the test environment")
	gexec.KillAndWait(5 * time.Second)
	weixinServer.Close()
})

var _ = Describe("Weixin", func() {
	Context("Weixin", func() {
		var (
			provider identityprovider.OAuthProvider
			err      error
		)
		It("should configure successfully", func() {
			configYAML := `
clientID: de6ff8bed0304e487b6e
clientSecret: 2b70536f79ec8d2939863509d05e2a71c268b9af
redirectURL: "https://ks-console.kubesphere-system.svc/oauth/redirect/weixin"
`
			config := mustUnmarshalYAML(configYAML)
			factory := weixinProviderFactory{}
			provider, err = factory.Create(config)
			Expect(err).Should(BeNil())
			expected := &weixinProvider{
				ClientID:     "de6ff8bed0304e487b6e",
				ClientSecret: "2b70536f79ec8d2939863509d05e2a71c268b9af",
				RedirectURL:  "https://ks-console.kubesphere-system.svc/oauth/redirect/weixin",
				Scopes:       []string{"snsapi_login"},
				Endpoint: endpoint{
					AuthURL:     authURL,
					TokenURL:    tokenURL,
					UserInfoURL: userInfoURL,
				},
				Config: &oauth2.Config{
					ClientID:     "de6ff8bed0304e487b6e",
					ClientSecret: "2b70536f79ec8d2939863509d05e2a71c268b9af",
					Endpoint: oauth2.Endpoint{
						AuthURL:  authURL,
						TokenURL: tokenURL,
					},
					RedirectURL: "https://ks-console.kubesphere-system.svc/oauth/redirect/weixin",
					Scopes:      []string{"snsapi_login"},
				},
			}
			Expect(provider).Should(Equal(expected))
		})
		It("should configure successfully", func() {
			config := options.DynamicOptions{
				"clientID":     "de6ff8bed0304e487b6e",
				"clientSecret": "2b70536f79ec8d2939863509d05e2a71c268b9af",
				"redirectURL":  "https://ks-console.kubesphere-system.svc/oauth/redirect/weixin",
				"endpoint": options.DynamicOptions{
					"authURL":     fmt.Sprintf("%s/connect/qrconnect", weixinServer.URL),
					"tokenURL":    fmt.Sprintf("%s/sns/oauth2/access_token", weixinServer.URL),
					"userInfoURL": fmt.Sprintf("%s/sns/userinfo", weixinServer.URL),
				},
			}
			factory := weixinProviderFactory{}
			provider, err = factory.Create(config)
			Expect(err).Should(BeNil())
			expected := &weixinProvider{
				ClientID:     "de6ff8bed0304e487b6e",
				ClientSecret: "2b70536f79ec8d2939863509d05e2a71c268b9af",
				RedirectURL:  "https://ks-console.kubesphere-system.svc/oauth/redirect/weixin",
				Scopes:       []string{"snsapi_login"},
				Endpoint: endpoint{
					AuthURL:     fmt.Sprintf("%s/connect/qrconnect", weixinServer.URL),
					TokenURL:    fmt.Sprintf("%s/sns/oauth2/access_token", weixinServer.URL),
					UserInfoURL: fmt.Sprintf("%s/sns/userinfo", weixinServer.URL),
				},
				Config: &oauth2.Config{
					ClientID:     "de6ff8bed0304e487b6e",
					ClientSecret: "2b70536f79ec8d2939863509d05e2a71c268b9af",
					Endpoint: oauth2.Endpoint{
						AuthURL:  fmt.Sprintf("%s/connect/qrconnect", weixinServer.URL),
						TokenURL: fmt.Sprintf("%s/sns/oauth2/access_token", weixinServer.URL),
					},
					RedirectURL: "https://ks-console.kubesphere-system.svc/oauth/redirect/weixin",
					Scopes:      []string{"snsapi_login"},
				},
			}
			Expect(provider).Should(Equal(expected))
		})
		It("should login successfully", func() {
			url, _ := url.Parse("https://ks-console.kubesphere-system.svc/oauth/redirect/test?code=00000")
			req := &http.Request{URL: url}
			identity, err := provider.IdentityExchangeCallback(req)
			Expect(err).Should(BeNil())
			Expect(identity.GetUserID()).Should(Equal("unionid"))
			Expect(identity.GetUsername()).Should(Equal("nickname"))
			Expect(identity.GetEmail()).Should(Equal(""))
		})
	})
})

func mustUnmarshalYAML(data string) options.DynamicOptions {
	var dynamicOptions options.DynamicOptions
	_ = yaml.Unmarshal([]byte(data), &dynamicOptions)
	return dynamicOptions
}
