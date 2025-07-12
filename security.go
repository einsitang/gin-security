package ginse

import (
	"fmt"
	"log"
	"slices"

	security "github.com/einsitang/go-security"
	"github.com/gin-gonic/gin"
)

type DoPrincipalHandler func(c *gin.Context) (security.SecurityPrincipal, map[string]string, error)
type GinSe interface {
	// return white list , white list will skip check
	WhiteList() []string

	// gin global middleware
	WithSentinel() gin.HandlerFunc

	// gin endpoint middleware
	WithGuard(express string) gin.HandlerFunc

	// forbidden handler (403)
	//
	// if forbidden handler is not set, will use default handler
	DoForbiddenHandler(gin.HandlerFunc)

	// unauthorized handler (401)
	//
	// if unauthorized handler is not set, will use default handler
	DoUnauthorizedHandler(gin.HandlerFunc)

	DoPrincipalHandler(DoPrincipalHandler)
}

type ginSe struct {
	TokenName      string
	AuthFromHeader bool

	sentinel  security.Sentinel
	whiteList []string

	// callback handlers

	forbiddenHandler    gin.HandlerFunc
	unauthorizedHandler gin.HandlerFunc
	principalHandler    DoPrincipalHandler
}

func (g *ginSe) WhiteList() []string {
	return g.whiteList
}

func (g *ginSe) WithSentinel() gin.HandlerFunc {
	return func(c *gin.Context) {

		fullpath := c.FullPath()
		// 跳过白名单
		if slices.Contains(g.WhiteList(), fullpath) {
			c.Next()
			return
		}

		// 恢复 principal
		principal, customParam, err := g.principalHandler(c)

		if err != nil {
			// 401
			log.Println(err)
			g.unauthorizedHandler(c)
			return
		}

		if principal == nil {
			// 401
			g.unauthorizedHandler(c)
			return
		}

		method := c.Request.Method
		endpoint := fmt.Sprintf("%s %s", method, fullpath)

		chekced, _ := g.sentinel.Check(endpoint, principal, customParam)
		if chekced {
			c.Next()
		} else {
			g.forbiddenHandler(c)
		}
	}
}

func (g *ginSe) WithGuard(express string) gin.HandlerFunc {
	guard, err := security.NewGuard(express)
	if err != nil {
		log.Fatal(err)
		panic(err.Error())
	}
	return func(c *gin.Context) {
		params := map[string]any{}
		for k, vs := range c.Request.URL.Query() {
			params[k] = vs[0]
		}

		// 恢复 principal
		principal, customParam, err := g.principalHandler(c)
		if err != nil {
			// 401
			log.Println(err)
			g.unauthorizedHandler(c)
			return
		}
		if principal == nil {
			// 401
			g.unauthorizedHandler(c)
			return
		}

		var context = &security.SecurityContext{
			Principal:    principal,
			Params:       params,
			CustomParams: customParam,
		}
		checked, err := guard.Check(context)
		if err != nil {
			log.Println(err)
			// 401
			g.unauthorizedHandler(c)
			return
		}
		if checked {
			c.Next()
		} else {
			// 403
			g.forbiddenHandler(c)
		}

	}
}

func (g *ginSe) DoForbiddenHandler(h gin.HandlerFunc) {
	g.forbiddenHandler = h
}

func (g *ginSe) DoUnauthorizedHandler(h gin.HandlerFunc) {
	g.unauthorizedHandler = h
}

func (g *ginSe) DoPrincipalHandler(h DoPrincipalHandler) {
	g.principalHandler = h
}

type GinSecurityOption func(*ginSe)

func WithWhiteList(whiteList []string) GinSecurityOption {
	return func(g *ginSe) {
		g.whiteList = whiteList
	}
}
func New(options ...GinSecurityOption) (GinSe, error) {
	sentinel, err := security.NewSentinel()
	if err != nil {
		return nil, err
	}

	tokenName := "Authorization"
	authFromHeader := true
	whiteList := []string{}

	se := &ginSe{TokenName: tokenName, AuthFromHeader: authFromHeader, sentinel: sentinel, whiteList: whiteList}
	se.forbiddenHandler = defaultForbiddenHandler
	se.unauthorizedHandler = defaultUnauthorizedHandler
	se.principalHandler = defaultPrincipalHandler

	for _, option := range options {
		option(se)
	}

	return se, nil
}

func defaultPrincipalHandler(c *gin.Context) (security.SecurityPrincipal, map[string]string, error) {
	panic("not implement principalHandler")
}

func defaultForbiddenHandler(c *gin.Context) {
	c.JSON(403, gin.H{
		"message": "forbidden",
	})
	c.Abort()
}

func defaultUnauthorizedHandler(c *gin.Context) {
	c.JSON(401, gin.H{
		"message": "unauthorized",
	})
	c.Abort()
}
