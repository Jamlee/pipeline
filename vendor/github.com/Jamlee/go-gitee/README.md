# go-gitee #

go-gitee is a Go client library for accessing the [Gitee API v5][].

go-gitee requires Go version 1.7 or greater.


## Usage ##

The go-gitee library does not directly handle authentication. Instead, when
creating a new client, pass an `http.Client` that can handle authentication for
you. The easiest and recommended way to do this is using the [oauth2][]
library, but you can always use any other library that provides an
`http.Client`. If you have an OAuth2 access token (for example, a [personal
API token][]), you can use it with the oauth2 library using:

```go
import "golang.org/x/oauth2"
import "github.com/weilaihui/go-gitee/gitee"


ctx := context.Background()
conf := &oauth2.Config{
    ClientID:     "{ClientID}",
    ClientSecret: "{ClientSecret}",
    Scopes:       "{Scopes}",
    Endpoint: oauth2.Endpoint{
        AuthURL:  "https://gitee.com/oauth/auth",
        TokenURL: "https://gitee.com/oauth/token",
    },
}
token,err := conf.PasswordCredentialsToken(ctx,"{username}","{password}")

tp := gitee.OAuthTransport{
	Token: token,
}

client := gitee.NewClient(tp.Client())

user, _, err := client.Users.Get(ctx, "")
if err != nil {
	fmt.Printf("\nerror: %v\n", err)
	return
}

fmt.Printf("\n%v\n", gitee.Stringify(user))
fmt.Printf("\n%v\n", *user.Login)
```

The services of a client divide the API into logical chunks and correspond to
the structure of the Gitee API documentation at
https://gitee.com/api/v5/swagger.

### Accepted Status ###

Some endpoints may return a 202 Accepted status code, meaning that the
information required is not yet ready and was scheduled to be gathered on
the GitHub side. Methods known to behave like this are documented specifying
this behavior.

To detect this condition of error, you can check if its type is
`*gitee.AcceptedError`:

```go
stats, _, err := client.Repositories.ListContributorsStats(ctx, org, repo)
if _, ok := err.(*gitee.AcceptedError); ok {
	log.Println("scheduled on Gitee side")
}
```

### Creating and Updating Resources ###

All structs for Gitee resources use pointer values for all non-repeated fields.
This allows distinguishing between unset fields and those set to a zero-value.
Helper functions have been provided to easily create these pointers for string,
bool, and int values. For example:

```go
// create a new private repository named "foo"
repo := &gitee.Repository{
	Name:    gitee.String("foo"),
	Private: gitee.Bool(true),
}
client.Repositories.Create(ctx, "", repo)
```

Users who have worked with protocol buffers should find this pattern familiar.

### Pagination ###

All requests for resource collections (repos, pull requests, issues, etc.)
support pagination. Pagination options are described in the
`gitee.ListOptions` struct and passed to the list methods directly or as an
embedded type of a more specific list options struct (for example
`gitee.PullRequestListOptions`). Pages information is available via the
`gitee.Response` struct.

```go
client := gitee.NewClient(nil)

opt := &gitee.RepositoryListByOrgOptions{
	ListOptions: gitee.ListOptions{PerPage: 10},
}
// get all pages of results
var allRepos []*gitee.Repository
for {
	repos, resp, err := client.Repositories.ListByOrg(ctx, "gitee", opt)
	if err != nil {
		return err
	}
	allRepos = append(allRepos, repos...)
	if resp.NextPage == 0 {
		break
	}
	opt.Page = resp.NextPage
}
```

For complete usage of go-gitee, see the full [package docs][].

[oauth2]: https://github.com/golang/oauth2
[oauth2 docs]: https://godoc.org/golang.org/x/oauth2
[personal API token]: https://github.com/blog/1509-personal-api-tokens
[package docs]: https://godoc.org/github.com/weilaihui/go-gitee/gitee
[GraphQL API v4]: https://developer.github.com/v4/
[shurcooL/githubql]: https://github.com/shurcooL/githubql

### Integration Tests ###

You can run integration tests from the `test` directory. See the integration tests [README](test/README.md).

## Roadmap ##

This library is being initially developed by go-github, 
so API methods will likely be implemented  like go-github. 
You can track the status of implementation in
[go-github][go-github]. Eventually, I would like to cover the entire
Gitee API, so contributions are of course [always welcome][contributing]. The
calling pattern is pretty well established, so adding new methods is relatively
straightforward.

[go-github]: https://github.com/google/go-github
[contributing]: CONTRIBUTING.md


## License ##

This library is distributed under the BSD-style license found in the [LICENSE](./LICENSE)
file.
