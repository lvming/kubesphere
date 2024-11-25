/*
 * Please refer to the LICENSE file in the root directory of the project.
 * https://github.com/kubesphere/kubesphere/blob/master/LICENSE
 */

package weixin

import (
	"encoding/json"
	"fmt"
	"github.com/mitchellh/mapstructure"
	"golang.org/x/oauth2"
	"io"
	"kubesphere.io/kubesphere/pkg/apiserver/authentication/identityprovider"
	"kubesphere.io/kubesphere/pkg/server/options"
	"net/http"
)

const (
	weixinIdentityProvider = "WeixinIdentityProvider"
	authURL                = "https://open.weixin.qq.com/connect/qrconnect"
	tokenURL               = "https://api.weixin.qq.com/sns/oauth2/access_token"
	userInfoURL            = "https://api.weixin.qq.com/sns/userinfo"
)

func init() {
	identityprovider.RegisterOAuthProviderFactory(&weixinProviderFactory{})
}

type weixinProvider struct {
	ClientID     string         `json:"clientID" yaml:"clientID"`
	ClientSecret string         `json:"-" yaml:"clientSecret"`
	RedirectURL  string         `json:"redirectURL" yaml:"redirectURL"`
	BridgeURL    string         `json:"bridgeURL" yaml:"bridgeURL"`
	Scopes       []string       `json:"scopes" yaml:"scopes"`
	Endpoint     endpoint       `json:"-" yaml:"-"`
	Config       *oauth2.Config `json:"-" yaml:"-"`
}

type endpoint struct {
	AuthURL     string `json:"authURL" yaml:"authURL"`
	TokenURL    string `json:"tokenURL" yaml:"tokenURL"`
	UserInfoURL string `json:"userInfoURL" yaml:"userInfoURL"`
}

type accessTokenResponse struct {
	AccessToken  string `json:"access_token"`
	ExpiresIn    uint64 `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	OpenID       string `json:"openid"`
	Scope        string `json:"scope"`
	UnionID      string `json:"unionid"`
	ErrCode      int    `json:"errcode"`
	ErrMsg       string `json:"errmsg"`
}

type weixinIdentity struct {
	UnionID    string `json:"unionid"`
	OpenID     string `json:"openid"`
	Nickname   string `json:"nickname"`
	HeadImgURL string `json:"headimgurl"`
	ErrCode    int    `json:"errcode"`
	ErrMsg     string `json:"errmsg"`
}

type weixinProviderFactory struct{}

func (wx *weixinProviderFactory) Type() string {
	return weixinIdentityProvider
}

func (wx *weixinProviderFactory) Create(opts options.DynamicOptions) (identityprovider.OAuthProvider, error) {
	var provider weixinProvider
	if err := mapstructure.Decode(opts, &provider); err != nil {
		return nil, err
	}
	if len(provider.Scopes) == 0 {
		provider.Scopes = []string{"snsapi_login"}
	}
	if provider.Endpoint.AuthURL == "" {
		provider.Endpoint.AuthURL = authURL
	}
	if provider.Endpoint.TokenURL == "" {
		provider.Endpoint.TokenURL = tokenURL
	}
	if provider.Endpoint.UserInfoURL == "" {
		provider.Endpoint.UserInfoURL = userInfoURL
	}
	// fixed options
	opts["endpoint"] = options.DynamicOptions{
		"authURL":     provider.Endpoint.AuthURL,
		"tokenURL":    provider.Endpoint.TokenURL,
		"userInfoURL": provider.Endpoint.UserInfoURL,
	}
	provider.Config = &oauth2.Config{
		ClientID:     provider.ClientID,
		ClientSecret: provider.ClientSecret,
		Endpoint: oauth2.Endpoint{
			AuthURL:  provider.Endpoint.AuthURL,
			TokenURL: provider.Endpoint.TokenURL,
		},
		RedirectURL: provider.RedirectURL,
		Scopes:      provider.Scopes,
	}
	return &provider, nil
}

func (wx weixinIdentity) GetUserID() string {
	return wx.UnionID
}

func (wx weixinIdentity) GetUsername() string {
	return wx.Nickname
}

func (wx weixinIdentity) GetEmail() string {
	return ""
}

func (wx *weixinProvider) getAccessToken(code string) (*accessTokenResponse, error) {
	req, err := http.NewRequest("GET", wx.Endpoint.TokenURL, nil)
	if err != nil {
		return nil, fmt.Errorf("weixin: failed to make request: %v", err)
	}
	q := req.URL.Query()
	q.Add("grant_type", "authorization_code")
	q.Add("appid", wx.ClientID)
	q.Add("secret", wx.ClientSecret)
	q.Add("code", code)
	req.URL.RawQuery = q.Encode()
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var accessTokenResponse accessTokenResponse
	err = json.Unmarshal(data, &accessTokenResponse)
	if err != nil {
		return nil, err
	}
	if accessTokenResponse.ErrCode != 0 {
		return nil, fmt.Errorf("weixin: get access token error: %s", accessTokenResponse.ErrMsg)
	}
	return &accessTokenResponse, nil
}

func (wx *weixinProvider) IdentityExchangeCallback(req *http.Request) (identityprovider.Identity, error) {
	code := req.URL.Query().Get("code")
	token, err := wx.getAccessToken(code)
	if err != nil {
		return nil, fmt.Errorf("weixin: failed to get access_token: %v", err)
	}
	// get userInfo
	req, err = http.NewRequest("GET", wx.Endpoint.UserInfoURL, nil)
	if err != nil {
		return nil, fmt.Errorf("weixin: failed to make request: %v", err)
	}
	q := req.URL.Query()
	q.Add("access_token", token.AccessToken)
	q.Add("openid", token.OpenID)
	q.Add("lang", "zh_CN")
	req.URL.RawQuery = q.Encode()
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var weixinIdentity weixinIdentity
	err = json.Unmarshal(data, &weixinIdentity)
	if err != nil {
		return nil, err
	}
	if weixinIdentity.ErrCode != 0 {
		return nil, fmt.Errorf("weixin: get user info error: %s", weixinIdentity.ErrMsg)
	}
	if weixinIdentity.UnionID == "" {
		return nil, fmt.Errorf("weixin: empty unionid")
	}
	return weixinIdentity, nil
}
