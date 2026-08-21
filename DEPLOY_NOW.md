# Deploy Now

## Render

Use a **new** Web Service because the previous service was configured with the wrong runtime. Set Runtime/Language to **Docker**.

The current Render error `go.mod file not found` happens because Render is running a Go build. This package removes that path and supplies a Docker build instead.

After deployment, check:

`https://YOUR-SERVICE.onrender.com/health`

Expected response contains:

`"ok":true`

Do not publish the Android app until the HTTPS server URL is working and the app is rebuilt with that URL.
