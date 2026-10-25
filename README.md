# IndieAuth Helper

A [IndieAuth](https://indieauth.spec.indieweb.org/) helper library for JavaScript and TypeScript, implementing the IndieAuth Living Standard (11 July 2024).

```bash
npm install indieauth-helper
```

```ts
import IndieAuth from "indieauth-helper";

const auth = new IndieAuth({
  me: "https://user.example/",
  clientId: "https://app.example/",
  redirectUri: "https://app.example/callback",
  secret: "a long random string",
});

await auth.discover();
const authUrl = await auth.getAuthUrl({ scopes: ["profile", "create"] });
```

Full documentation: [https://grantcodes.github.io/indieauth-helper/](https://grantcodes.github.io/indieauth-helper/)

## Thanks

- [martymcguire](https://github.com/martymcguire) - For the idea and building a lot of the functionality
- [sknebel](https://github.com/sknebel) - For helping with the rel scraping function
- [Zegnat](https://github.com/Zegnat) - For helping with the rel scraping function
- [myfreeweb](https://github.com/myfreeweb) - For fixing Link header handling and help with Accept headers
- [00dani](https://github.com/00dani) - For fixing base tag support in the rel scraper
- [cweiske](https://github.com/cweiske) - For fixing the 'me' domain check
