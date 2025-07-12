package main

import (
	"log"
	"net/http"

	ginse "github.com/einsitang/gin-security"
	"github.com/einsitang/go-security"
	"github.com/gin-gonic/gin"
)

type ExamplePrincipal struct {
	id    string
	roles []string
}

func (e *ExamplePrincipal) Groups() []string {
	return nil
}
func (e *ExamplePrincipal) Id() string {
	return e.id
}
func (e *ExamplePrincipal) Permissions() []string {
	return nil
}
func (e *ExamplePrincipal) Roles() []string {
	return e.roles
}

func main() {
	whiteList := []string{"/api/v1/login"}
	gse, err := ginse.New(ginse.WithWhiteList(whiteList), ginse.WithRules("rule.txt"))
	// gse,err := ginse.New(ginse.WithWhiteList(whiteList))
	if err != nil {
		panic(err)
	}

	// Pricipal Handler
	gse.DoPrincipalHandler(func(c *gin.Context) (security.SecurityPrincipal, map[string]string, error) {

		// tokenName := "Authorization"
		// var tokenValue string

		// // from cookie
		// tokenValueFromCookie, err := c.Cookie(tokenName)
		// if err != nil {
		// 	return nil, nil, err
		// }
		// tokenValue = tokenValueFromCookie

		// // from header
		// tokenValue = c.GetHeader(tokenName)
		// if tokenName == "" {
		// 	return nil, nil, errors.New("not found token")
		// }
		// tokenValue, isFound := strings.CutPrefix(tokenValue, "Bearer ")
		// if !isFound {
		// 	return nil, nil, errors.New("token format error")
		// }

		// jwt parse
		// jwtUtils.parse(tokenValue)

		// read session from storage
		// redis
		// mysql
		// memory

		// principal for demo
		principal := &ExamplePrincipal{
			id: "test",
			roles: []string{
				"admin",
			},
		}
		// 自定义参数
		customParams := map[string]string{}

		return principal, customParams, nil
	})

	// 注册 401 hander 认证失败 handler
	// gse.DoUnauthorizedHandler(func(c *gin.Context) {
	// 	c.JSON(401, gin.H{
	// 		"message": "unauthorized",
	// 	})
	// 	c.Abort()
	// })

	// // 注册 403 hander 权限验证失败 handler
	// gse.DoForbiddenHandler(func(c *gin.Context) {
	// 	c.JSON(403, gin.H{
	// 		"message": "forbidden",
	// 	})
	// 	c.Abort()
	// })

	r := gin.Default()
	r.Use(gin.Recovery())
	// WithSentinel 用于gin全局路由拦截，会再使用内部路由树匹配
	r.Use(gse.WithSentinel())

	r.POST("/api/v1/login", func(c *gin.Context) {
		username := "hello"
		param := map[string]any{
			"username": username,
		}
		_ = param
		expireTime := -1
		_ = expireTime
		accessToken := "" // jwt

		c.JSON(200, gin.H{
			"accessToken": accessToken,
		})
	})

	r.POST("/api/v1/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"test": "POST METHOD IS OK",
		})
	})

	r.GET("/api/v1/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"test": "GET METHOD IS OK",
		})
	})

	// WithGuard 仅对当前 gin 的路由结果进行拦截检查，不建议 WithGuard 与 WithSentinel 一起使用, 容易造成双从检查
	express := "allow:Role('admin') and $age > 18"
	r.GET("/api/v1/users", gse.WithGuard(express), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"helo": "world",
		})
	})

	log.Fatal(r.Run())

}
