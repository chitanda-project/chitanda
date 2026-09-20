package controller

import (
	"errors"
	"fmt"
	"net/http"
	"time"

	"x-ui/web/entity"
	"x-ui/web/global"
	"x-ui/web/job"
	"x-ui/web/service"
	"x-ui/web/session"

	"github.com/gin-gonic/gin"
)

type updateUserForm struct {
	OldUsername string `json:"oldUsername" form:"oldUsername"`
	OldPassword string `json:"oldPassword" form:"oldPassword"`
	NewUsername string `json:"newUsername" form:"newUsername"`
	NewPassword string `json:"newPassword" form:"newPassword"`
}

type updateSecretForm struct {
	LoginSecret string `json:"loginSecret" form:"loginSecret"`
}

type SettingController struct {
	settingService service.SettingService
	userService    service.UserService
	panelService   service.PanelService
	xrayService    service.XrayService
}

func NewSettingController(g *gin.RouterGroup) *SettingController {
	a := &SettingController{}
	a.initRouter(g)
	return a
}

func (a *SettingController) initRouter(g *gin.RouterGroup) {
	g = g.Group("/setting")

	g.POST("/all", a.getAllSetting)
	g.POST("/defaultSettings", a.getDefaultSettings)
	g.POST("/update", a.updateSetting)
	g.POST("/updateUser", a.updateUser)
	g.POST("/restartPanel", a.restartPanel)
	g.GET("/getDefaultJsonConfig", a.getDefaultXrayConfig)
	g.POST("/updateUserSecret", a.updateSecret)
	g.POST("/getUserSecret", a.getUserSecret)
	g.POST("/updateGeoNow", a.updateGeoNow)
}

func (a *SettingController) getAllSetting(c *gin.Context) {
	allSetting, err := a.settingService.GetAllSetting()
	if err != nil {
		jsonMsg(c, I18nWeb(c, "pages.settings.toasts.getSettings"), err)
		return
	}
	jsonObj(c, allSetting, nil)
}

func (a *SettingController) getDefaultSettings(c *gin.Context) {
	result, err := a.settingService.GetDefaultSettings(c.Request.Host)
	if err != nil {
		jsonMsg(c, I18nWeb(c, "pages.settings.toasts.getSettings"), err)
		return
	}
	jsonObj(c, result, nil)
}

func (a *SettingController) updateSetting(c *gin.Context) {
	allSetting := &entity.AllSetting{}
	err := c.ShouldBind(allSetting)
	if err != nil {
		jsonMsg(c, I18nWeb(c, "pages.settings.toasts.modifySettings"), err)
		return
	}
	err = a.settingService.UpdateAllSetting(allSetting)
	if err == nil {
		if ws := global.GetWebServer(); ws != nil {
			ws.ReloadUpdateGeoJob()
		}
	}
	jsonMsg(c, I18nWeb(c, "pages.settings.toasts.modifySettings"), err)
}

func (a *SettingController) updateUser(c *gin.Context) {
	form := &updateUserForm{}
	err := c.ShouldBind(form)
	if err != nil {
		jsonMsg(c, I18nWeb(c, "pages.settings.toasts.modifySettings"), err)
		return
	}
	user := session.GetLoginUser(c)
	if user.Username != form.OldUsername || user.Password != form.OldPassword {
		jsonMsg(c, I18nWeb(c, "pages.settings.toasts.modifyUser"), errors.New(I18nWeb(c, "pages.settings.toasts.originalUserPassIncorrect")))
		return
	}
	if form.NewUsername == "" || form.NewPassword == "" {
		jsonMsg(c, I18nWeb(c, "pages.settings.toasts.modifyUser"), errors.New(I18nWeb(c, "pages.settings.toasts.userPassMustBeNotEmpty")))
		return
	}
	err = a.userService.UpdateUser(user.Id, form.NewUsername, form.NewPassword)
	if err == nil {
		user.Username = form.NewUsername
		user.Password = form.NewPassword
		session.SetLoginUser(c, user)
	}
	jsonMsg(c, I18nWeb(c, "pages.settings.toasts.modifyUser"), err)
}

func (a *SettingController) restartPanel(c *gin.Context) {
	err := a.panelService.RestartPanel(time.Second * 3)
	jsonMsg(c, I18nWeb(c, "pages.settings.restartPanel"), err)
}

func (a *SettingController) updateSecret(c *gin.Context) {
	form := &updateSecretForm{}
	err := c.ShouldBind(form)
	if err != nil {
		jsonMsg(c, I18nWeb(c, "pages.settings.toasts.modifySettings"), err)
	}
	user := session.GetLoginUser(c)
	err = a.userService.UpdateUserSecret(user.Id, form.LoginSecret)
	if err == nil {
		user.LoginSecret = form.LoginSecret
		session.SetLoginUser(c, user)
	}
	jsonMsg(c, I18nWeb(c, "pages.settings.toasts.modifyUser"), err)
}

func (a *SettingController) getUserSecret(c *gin.Context) {
	loginUser := session.GetLoginUser(c)
	user := a.userService.GetUserSecret(loginUser.Id)
	if user != nil {
		jsonObj(c, user, nil)
	}
}

func (a *SettingController) getDefaultXrayConfig(c *gin.Context) {
	defaultJsonConfig, err := a.settingService.GetDefaultXrayConfig()
	if err != nil {
		jsonMsg(c, I18nWeb(c, "pages.settings.toasts.getSettings"), err)
		return
	}
	jsonObj(c, defaultJsonConfig, nil)
}

type updateGeoForm struct {
	Sources string `json:"sources" form:"sources"`
}

func (a *SettingController) updateGeoNow(c *gin.Context) {
	var form updateGeoForm
	_ = c.ShouldBind(&form)

	sources := form.Sources
	if sources == "" {
		var err error
		sources, err = a.settingService.GetGeoAutoUpdateSources()
		if err != nil || sources == "" {
			sources = "Loyalsoldier"
		}
	}
	updated, unchanged, err := job.UpdateGeo(sources, &a.xrayService)
	if err != nil {
		jsonMsg(c, I18nWeb(c, "pages.settings.toasts.updateGeo"), err)
		return
	}
	msg := fmt.Sprintf(I18nWeb(c, "pages.settings.toasts.updateGeoSuccess"), len(updated), len(unchanged))
	c.JSON(http.StatusOK, entity.Msg{
		Success: true,
		Msg:     msg,
		Obj: gin.H{
			"updated":   updated,
			"unchanged": unchanged,
		},
	})
}

