## This repo was forked from https://github.com/ginuerzh/gost 

This repo was forked for personal use and modified for my needs to use as local proxy for tunneling trafic via remote proxy with auth. Actually I deleted all unused protocols like udp and websockes.

Only http and socks are left.

If you want to use it in your project, you may use it as follows:

```golang
    import gost "github.com/far4599/gost-minimal"

    func CreateProxy() error {
        route := gost.Route{
            ServeNodes: []string{":8080",}, // local proxy port
            ChainNodes: []string{"http://user:password@remote_proxy_ip:proxy_port",}, // remote proxy with creds
            Retries:    0,
        }
    
        rts, err := route.GenRouters()
        if err != nil {
            log.Panic(err)
        }
    
        return rts[0].Serve()
    }
```
