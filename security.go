package ginse

import (
	"fmt"
	"log"
	"net/http"
	"slices"

	security "github.com/einsitang/go-security"
	"github.com/gin-gonic/gin"
)

type DoPrincipalHandler func(c *gin.Context) (security.SecurityPrincipal, map[string]string, error)
type GinSe interface {
	// return white list , white list will skip check
	WhiteList() []string

	/*
		gin global middleware with go-security endpoint router

		It is not recommended to use `WithGuard` and `WithSentinel`` together.
	*/
	WithSentinel() gin.HandlerFunc

	/*
		gin endpoint middleware

		It is not recommended to use `WithGuard` and `WithSentinel`` together.
	*/
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

		// 404
		if fullpath == "" {
			c.Next()
			return
		}

		// 跳过白名单
		if slices.Contains(g.WhiteList(), fullpath) {
			c.Next()
			return
		}

		// recovery principal
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
		var endpoint string
		if c.Request.URL.RawQuery != "" {
			// 带参数
			endpoint = fmt.Sprintf("%s %s?%s", method, fullpath, c.Request.URL.RawQuery)
		} else {
			// 不带参数
			endpoint = fmt.Sprintf("%s %s", method, fullpath)
		}

		chekced, err := g.sentinel.Check(endpoint, principal, customParam)
		if err != nil {
			switch err.(type) {
			case security.EndpointNotFoundError:
				// endpoint not match in sentinel router , just let it passed :-)
				c.Next()
				return
			}
			log.Printf("[warring]sentinel.check %s error: %s \n", endpoint, err)
		}
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
		log.Println(err)
		panic(err.Error())
	}
	return func(c *gin.Context) {

		fullpath := c.FullPath()

		// 跳过白名单
		if slices.Contains(g.WhiteList(), fullpath) {
			c.Next()
			return
		}

		params := map[string]any{}
		for k, vs := range c.Request.URL.Query() {
			params[k] = vs[0]
		}

		// recovery principal
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

type GinSeOption func(*ginSe) error

func WithWhiteList(whiteList []string) GinSeOption {
	return func(g *ginSe) error {
		g.whiteList = whiteList
		return nil
	}
}

func WithRules(ruleFile string) GinSeOption {
	return func(g *ginSe) error {
		sentinel, err := security.NewSentinel(security.WithConfig(ruleFile))
		if err != nil {
			return err
		}
		g.sentinel = sentinel
		return nil
	}
}
func New(options ...GinSeOption) (GinSe, error) {
	se := &ginSe{
		forbiddenHandler:    defaultForbiddenHandler,
		unauthorizedHandler: defaultUnauthorizedHandler,
		principalHandler:    defaultPrincipalHandler,
	}

	for _, option := range options {
		option(se)
	}

	if se.sentinel == nil {
		sentinel, err := security.NewSentinel()
		if err != nil {
			return nil, err
		}
		se.sentinel = sentinel
	}

	if se.whiteList == nil {
		se.whiteList = []string{}
	}

	return se, nil
}

func defaultPrincipalHandler(c *gin.Context) (security.SecurityPrincipal, map[string]string, error) {
	panic("not implement principalHandler")
}

func defaultForbiddenHandler(c *gin.Context) {
	c.JSON(http.StatusForbidden, gin.H{
		"message": "forbidden",
	})
	c.Abort()
}

func defaultUnauthorizedHandler(c *gin.Context) {
	c.JSON(http.StatusUnauthorized, gin.H{
		"message": "unauthorized",
	})
	c.Abort()
}
