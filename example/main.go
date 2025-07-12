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
	gse, _ := ginse.New(ginse.WithWhiteList(whiteList))

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
	// r.Use(se.WithSentinel())

	r.POST("/v1/api/login", func(c *gin.Context) {
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
	express := "allow:Role('admin') and $age > 18"
	r.GET("/v1/api/users", gse.WithGuard(express), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"helo": "world",
		})
	})

	log.Fatal(r.Run())

}
