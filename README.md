# gin-security

[![Release](https://img.shields.io/github/v/release/einsitang/gin-security.svg?style=flat-square)](https://github.com/einsitang/gin-security/releases)

`gin-security` 是一个基于 [Gin](https://github.com/gin-gonic/gin) 和 [go-security](https://github.com/einsitang/go-security) 的权限控制中间件，支持 **基于角色/权限的访问控制**（RBAC）以及 **表达式规则验证**。

---

## 📦 安装

```bash
go get github.com/einsitang/gin-security
```

---

## 🔐 快速开始

### 1. 初始化 GinSe 实例

使用 [ginse.New()](file:///Users/einsitang/github/sevlow/gin-security/security.go#L208-L232) 创建一个安全中间件实例，并配置白名单和规则文件：

```go
gse, err := ginse.New(
    // 可选
    ginse.WithWhiteList([]string{"/api/v1/login"}),
    // 可选
    ginse.WithRules("rule.txt"),
)
if err != nil {
    panic(err)
}
```

`GinSe` 可选配置:
- WithWhiteList 设置不需要进行权限校验的路径。
- WithRules：指定权限规则文件路径（如 [rule.txt](./example/rule.txt)）快速构建 端点 与 路由表达式 的映射关系

---

### 2. 设置 Principal Handler

Principal 是当前请求用户的抽象表示。你需要注册 DoPrincipalHandler 来返回当前用户信息：

```go
gse.DoPrincipalHandler(func(c *gin.Context) (security.SecurityPrincipal, map[string]string, error) {
    // 需要自行实现 从 gin.Context 中获取凭证
    // 可以从 jwt 解签后获取
    // 可以从 memory / redis / db 中的 session 恢复用户权限信息 (Principal)

    // example
    principal := &ExamplePrincipal{
        id: "test",
        roles: []string{"admin"},
    }
    customParams := map[string]string{} // 可选自定义参数
    return principal, customParams, nil
})
```

其中 `ExamplePrincipal` 需要实现 `SecurityPrincipal` 接口：

```go
type ExamplePrincipal struct {
    id    string
    roles []string
}

func (e *ExamplePrincipal) Groups() []string     { return nil }
func (e *ExamplePrincipal) Id() string           { return e.id }
func (e *ExamplePrincipal) Permissions() []string { return nil }
func (e *ExamplePrincipal) Roles() []string      { return e.roles }
```

---

### 3. 自定义 401/403 处理器（可选）

你可以通过以下方式自定义未授权或权限不足时的响应：

以下是默认实现

```go
gse.DoUnauthorizedHandler(func(c *gin.Context) {
    c.JSON(http.StatusForbidden, gin.H{"message": "unauthorized"})
    c.Abort()
})

gse.DoForbiddenHandler(func(c *gin.Context) {
    c.JSON(http.StatusUnauthorized, gin.H{"message": "forbidden"})
    c.Abort()
})
```

---

## 🛡️ 中间件使用方式

### ✅ 全局中间件

使用 `WithSentinel()` 作为全局中间件，根据规则文件自动拦截并验证请求：

```go
r.Use(gse.WithSentinel())
```

> ⚠️ 注意：同时使用 [WithGuard](./security.go#L29-L29) 和 [WithSentinel](./security.go#L22-L22) 时需要考虑路由冲突问题

---

### ✅ 局部中间件（推荐）

使用 [WithGuard(express)](./security.go#L120-L175) 对某个具体路由进行权限控制：

```go

express := "allow:Role('admin') and $age > 18"
r.GET("/api/v1/users", gse.WithGuard(express), func(c *gin.Context) {
    c.JSON(http.StatusOK, gin.H{"hello": "world"})
})

// curl -X GET http://domain/api/v1/users?age=19 checked passed : true
```

表达式含义如下：

| 表达式                         | 含义                        |
|------------------------------|-----------------------------|
| `allow:Role('admin')`        | 用户角色中包含 `admin` 则放行  |
| `allow:Permission('write')`  | 用户具有 `write` 权限  则放行  |
| `$age > 18`                  | 请求参数中 `age > 18`         |
| deny:Role('guest')`          | 用户角色包含 `guest`  则禁行   |

---

## 🧩 规则文件格式（rule.txt 示例）

在 [rule.txt](./example/rule.txt) 中定义全局路由的权限规则：

```
GET /api/v1/test, allow:Role('admin')
POST /api/v1/test, allow:Permission('user.create')
```

每行表示一个路由规则，格式为：

```
<method> <pattern>, <expression>
```

例如：

```
GET /api/v1/users?age=:age, allow:Role('admin') and $age > 18
POST /api/v1/users, allow:Permission('user.create')
```

method 可选,缺少则通配所有,可以使用 `/` 符分割:

```
// GET
GET /api/v1/users, allow: 1 == 1

// GET POST
GET/POST /api/v2/users, allow: Roles('admin','manager')

// 忽略则通配
/api/v3/users, deny: !Role('admin')
```
---

## 📌 注意事项

- `Principal` 必须实现 `security.SecurityPrincipal` 接口。
- 白名单路径不会经过权限检查。
- 表达式语法请参考 [`go-security`](https://github.com/einsitang/go-security) 文档。

---

## 📘 参考资料

- [go-security GitHub](https://github.com/einsitang/go-security)
- [Gin GitHub](https://github.com/gin-gonic/gin)

---

## ✅ 示例项目

完整示例可参考：[example](./example)

---

如需进一步帮助，请查看 `go-security` 的文档或提交 issue 到本项目的 GitHub。
