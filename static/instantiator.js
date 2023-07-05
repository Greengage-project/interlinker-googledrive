const {
  CssBaseline,
  ThemeProvider,
  Typography,
  Container,
  createTheme,
  Box,
  Button,
  Input,
  LinearProgress,
  Avatar,
  Grid,
  Select,
  MenuItem,
  TextField,
} = MaterialUI;

var { domain, basepath, datafrombackend } = jQuery("#data").data();
const origin = domain.PROTOCOL + domain.SERVER_NAME;
//console.log("ORIGIN", origin);

const http = axios.create({
  headers: {
    "Content-type": "application/json",
  },
});

const bytesToSize = (bytes, decimals = 2) => {
  if (bytes === 0) {
    return "0 Bytes";
  }

  const k = 1024;
  const dm = decimals < 0 ? 0 : decimals;
  const sizes = ["Bytes", "KB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB"];
  const i = Math.floor(Math.log(bytes) / Math.log(k));

  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(dm))} ${sizes[i]}`;
};

const inIframe = window.location !== window.parent.location;
const hasOpener = window.opener && !window.opener.closed;

const sendMessage = (code, data, callback, callbackIframe, callbackOpener) => {
  if (inIframe) {
    window.parent.postMessage(
      {
        code: code,
        message: data,
      },
      origin
    );
    callbackIframe && callbackIframe();
  } else if (hasOpener) {
    window.opener.postMessage(
      {
        code: code,
        message: data,
      },
      origin
    );
    callbackOpener && callbackOpener();
  } else {
    callback && callback();
  }
};

class UploadFilesService {
  upload(file, onUploadProgress) {
    let formData = new FormData();

    formData.append("file", file);
    //console.log("Entra en UploadFilesService");
    //console.log("The basepath is");
    //console.log(basepath);
    return http.post(`${basepath}/assets`, formData, {
      headers: {
        "Content-Type": "multipart/form-data",
      },
      onUploadProgress,
    });
  }
  clone(id) {
    //console.log("clone method of UploadFilesService");
    //console.log(basepath);
    //console.log("post to :");
    //console.log(`${basepath}/assets/${id}/clone`);
    return http.post(`${basepath}/assets/${id}/clone`);
  }
  create(data) {
    //console.log("create method of UploadFilesService");
    //console.log(basepath);
    //console.log("post to :");
    //console.log(`${basepath}/api/v1/assets/empty`);

    return http.post(`${basepath}/api/v1/assets/empty`, data);
  }
  confirm(id) {
    //console.log("confirm method of UploadFilesService");
    //console.log(basepath);
    //console.log("post to :");
    //console.log(`${basepath}/api/v1/assets/${id}/persist`);

    return http.post(`${basepath}/api/v1/assets/${id}/persist`, null, {});
  }
}

const service = new UploadFilesService();

// Create a theme instance.
const theme = createTheme({
  components: {
    MuiInputBase: {
      styleOverrides: {
        input: {
          "&::placeholder": {
            opacity: 0.86,
            color: "#42526e",
          },
        },
      },
    },
  },
  palette: {
    action: {
      active: "#6b778c",
    },
    background: {
      default: "#f4f5f7",
      paper: "#ffffff",
    },
    error: {
      contrastText: "#ffffff",
      main: "#f44336",
    },
    mode: "light",
    primary: {
      contrastText: "#ffffff",
      main: "#0f97c7",
      main2: "#091a22",
    },
    success: {
      contrastText: "#ffffff",
      main: "#44c949",
    },
    text: {
      primary: "#172b4d",
      secondary: "#6b778c",
      contrastMain2: "#f3f3f3",
    },
    warning: {
      contrastText: "#ffffff",
      main: "#ff9800",
    },
  },
  shadows: [
    "none",
    "0px 1px 2px rgba(0, 0, 0, 0.12), 0px 0px 0px 1px rgba(0, 0, 0, 0.05)",
    "0px 2px 4px rgba(0, 0, 0, 0.15), 0px 0px 0px 1px rgba(0, 0, 0, 0.05)",
    "0 0 1px 0 rgba(0,0,0,0.31), 0 3px 4px -2px rgba(0,0,0,0.25)",
    "0 0 1px 0 rgba(0,0,0,0.31), 0 3px 4px -2px rgba(0,0,0,0.25)",
    "0 0 1px 0 rgba(0,0,0,0.31), 0 4px 6px -2px rgba(0,0,0,0.25)",
    "0 0 1px 0 rgba(0,0,0,0.31), 0 4px 6px -2px rgba(0,0,0,0.25)",
    "0 0 1px 0 rgba(0,0,0,0.31), 0 4px 8px -2px rgba(0,0,0,0.25)",
    "0 0 1px 0 rgba(0,0,0,0.31), 0 5px 8px -2px rgba(0,0,0,0.25)",
    "0 0 1px 0 rgba(0,0,0,0.31), 0 6px 12px -4px rgba(0,0,0,0.25)",
    "0 0 1px 0 rgba(0,0,0,0.31), 0 7px 12px -4px rgba(0,0,0,0.25)",
    "0 0 1px 0 rgba(0,0,0,0.31), 0 6px 16px -4px rgba(0,0,0,0.25)",
    "0 0 1px 0 rgba(0,0,0,0.31), 0 7px 16px -4px rgba(0,0,0,0.25)",
    "0 0 1px 0 rgba(0,0,0,0.31), 0 8px 18px -8px rgba(0,0,0,0.25)",
    "0 0 1px 0 rgba(0,0,0,0.31), 0 9px 18px -8px rgba(0,0,0,0.25)",
    "0 0 1px 0 rgba(0,0,0,0.31), 0 10px 20px -8px rgba(0,0,0,0.25)",
    "0 0 1px 0 rgba(0,0,0,0.31), 0 11px 20px -8px rgba(0,0,0,0.25)",
    "0 0 1px 0 rgba(0,0,0,0.31), 0 12px 22px -8px rgba(0,0,0,0.25)",
    "0 0 1px 0 rgba(0,0,0,0.31), 0 13px 22px -8px rgba(0,0,0,0.25)",
    "0 0 1px 0 rgba(0,0,0,0.31), 0 14px 24px -8px rgba(0,0,0,0.25)",
    "0 0 1px 0 rgba(0,0,0,0.31), 0 16px 28px -8px rgba(0,0,0,0.25)",
    "0 0 1px 0 rgba(0,0,0,0.31), 0 18px 30px -8px rgba(0,0,0,0.25)",
    "0 0 1px 0 rgba(0,0,0,0.31), 0 20px 32px -8px rgba(0,0,0,0.25)",
    "0 0 1px 0 rgba(0,0,0,0.31), 0 22px 34px -8px rgba(0,0,0,0.25)",
    "0 0 1px 0 rgba(0,0,0,0.31), 0 24px 36px -8px rgba(0,0,0,0.25)",
  ],
});

function App() {
  const [progress, setProgress] = React.useState(0);
  const [file, setFile] = React.useState(null);
  const [iframeKey, setIframeKey] = React.useState(null);
  const [created, setCreated] = React.useState(null);
  const [mimeType, setMimeType] = React.useState("docs");
  const [name, setName] = React.useState("");
  const [uri, setUri] = React.useState("");
  const [error, setError] = React.useState({
    key: "",
    value: "",
  });
  const [loading, setLoading] = React.useState(false);
  const maxFiles = 1;

  var onUploadProgress = (progressEvent) => {
    setProgress((100 * progressEvent.loaded) / progressEvent.total);
  };

  React.useEffect(() => {
    sendMessage("initialized");
  }, []);

  function getIdFromUrl(url) {
    //console.log("the url is: " + url);
    //console.log("match");
    //console.log(url.match(/[-\w]{25,}/));

    return url.match(/[-\w]{25,}/);
  }
  function isValidHttpUrl(string) {
    let url;

    try {
      //console.log("YES the url is valid: " + string);
      url = new URL(string);
    } catch (_) {
      return false;
    }

    return url.protocol === "http:" || url.protocol === "https:";
  }

  React.useEffect(() => {
    if (uri && !isValidHttpUrl(uri)) {
      setError({
        key: "uri",
        value: "URI invalid",
      });
    } else {
      setError({
        key: "",
        value: "",
      });
    }
  }, [uri]);

  const selectFile = (event) => {
    setLoading(true);
    var f = event.target.files[0];

    service
      .upload(f, onUploadProgress)
      .then((response) => {
        //console.log("RESPONSE UPLOAD", response.data);
        setFile(response.data);
        setProgress(0);
      })
      .finally(() => setLoading(false));
  };

  const confirmFile = () => {
    setLoading(true);

    service
      .confirm(file.id)
      .then((response) => {
        //console.log("RESPONSE CONFIRM", response.data);
        const dataToSend = {
          id: response.data.id,
        };
        sendMessage(
          "asset_created",
          dataToSend,
          () => setCreated(dataToSend),
          null,
          window.close
        );
      })
      .finally(() => setLoading(false));
  };

  const submit = (data, fromId) => {
    //console.log("SENDING ", data);
    //console.log("FROM ID ", fromId);

    setLoading(true);
    const fn = fromId ? service.clone : service.create;
    fn(data)
      .then((response) => {
        //console.log("RESPONSE CONFIRM", response.data);
        const dataToSend = {
          id: response.data.id,
        };
        //console.log("Send asset created to the socket of frontend");
        sendMessage(
          "asset_created",
          dataToSend,
          () => setCreated(dataToSend),
          null,
          window.close
        );
      })
      .finally(() => setLoading(false));
  };

  const handleChange = (event) => {
    setMimeType(event.target.value);
  };

  const documentTypes = {
    docs: {
      value: "docs",
      label: "Document",
      icon: "https://ssl.gstatic.com/docs/doclist/images/mediatype/icon_1_document_x32.png",
    },
    spreadsheet: {
      value: "spreadsheet",
      label: "Spreadsheet",
      icon: "https://ssl.gstatic.com/docs/doclist/images/mediatype/icon_1_spreadsheet_x32.png",
    },
    slides: {
      value: "slide",
      label: "Slide",
      icon: "https://ssl.gstatic.com/docs/doclist/images/mediatype/icon_1_presentation_x32.png",
    },
    drawing: {
      value: "drawing",
      label: "Drawing",
      icon: "https://ssl.gstatic.com/docs/doclist/images/mediatype/icon_1_drawing_x32.png",
    },
    site: {
      value: "site",
      label: "Site",
      icon: "https://ssl.gstatic.com/docs/doclist/images/mediatype/icon_1_site_x32.png",
    },
    form: {
      value: "form",
      label: "Form",
      icon: "https://ssl.gstatic.com/docs/doclist/images/mediatype/icon_1_form_x32.png",
    },
    jamboard: {
      value: "jamboard",
      label: "Jamboard",
      icon: "https://cdn-icons-png.flaticon.com/512/2965/2965289.png",
    },
    // "map": {
    //   "value": "map",
    //   "label": "Map",
    //   "icon": "https://ssl.gstatic.com/docs/doclist/images/mediatype/icon_1_map_x32.png"
    // },
    // "fusiontable": {
    //   "value": "fusiontable",
    //   "label": "Fusion table",
    //   "icon": ""
    // }
  };
  // src={file.webViewLink}  //Previous Julen version
  let src = "";
  if (file) {
    if (file.webContentLink) {
      src = `https://docs.google.com/gview?url=${file.webContentLink}&embedded=true`;
    } else {
      if (file.webViewLink) {
        src = file.webViewLink;
      }
    }
  }

  return (
    <Container maxWidth="lg">
      <div>
        {created ? (
          <Box
            sx={{
              maxWidth: 450,
              mx: "auto",
              alignItems: "center",
            }}
          >
            <Box
              sx={{
                display: "flex",
                justifyContent: "center",
              }}
            >
              <Avatar src="" />
            </Box>
            <Box sx={{ mt: 2 }}>
              <Typography align="center" color="textPrimary" variant="h3">
                Resource created!
              </Typography>
            </Box>
            <Box sx={{ mt: 2 }}>
              <Typography
                align="center"
                color="textSecondary"
                variant="subtitle1"
              >
                The resource is now accessible for this task.
              </Typography>
            </Box>
            <Box
              sx={{
                display: "flex",
                justifyContent: "center",
                mt: 2,
              }}
            >
              <Button
                color="primary"
                variant="contained"
                href={`${basepath}/assets/${created.id}/view`}
              >
                Open resource
              </Button>
            </Box>
          </Box>
        ) : file ? (
          <React.Fragment>
            <iframe
              key={iframeKey}
              style={{ width: "100%", minHeight: "80vh", border: 0 }}
              src={src}
            />
            <Button
              variant="outlined"
              fullWidth
              sx={{ mt: 1 }}
              onClick={() => setIframeKey(iframeKey + 1)}
            >
              Refresh previewer
            </Button>
            <Button
              variant="contained"
              fullWidth
              sx={{ mt: 1 }}
              onClick={confirmFile}
            >
              Confirm upload
            </Button>
          </React.Fragment>
        ) : (
          <Box>
            <Grid container spacing={3}>
              <Grid item xs={12} md={6} lg={4}>
                <label htmlFor="contained-button-file">
                  <Input
                    id="contained-button-file"
                    type="file"
                    sx={{ display: "none" }}
                    onChange={selectFile}
                  />
                  <Typography variant="overline">
                    Import an existing file
                  </Typography>
                  <Box
                    sx={{
                      alignItems: "center",
                      border: 1,
                      borderRadius: 1,
                      borderColor: "divider",
                      display: "flex",
                      flexWrap: "wrap",
                      justifyContent: "center",
                      outline: "none",
                      p: 6,
                      "&:hover": {
                        backgroundColor: "action.hover",
                        cursor: "pointer",
                        opacity: 0.5,
                      },
                    }}
                  >
                    <Box
                      sx={{
                        "& img": {
                          width: 100,
                        },
                      }}
                    >
                      <img
                        alt="Select file"
                        src={`${basepath}/static/icon.svg`}
                      />
                    </Box>
                    <Box sx={{ p: 2 }}>
                      <Typography color="textPrimary" variant="h6">
                        {`Select file`}
                      </Typography>
                      <Box sx={{ mt: 2 }}>
                        <Typography color="textPrimary" variant="body1">
                          {`Drop file${maxFiles && maxFiles === 1 ? "" : "s"}`}{" "}
                          or click here
                        </Typography>
                      </Box>
                    </Box>
                  </Box>
                </label>
                {progress !== 0 && (
                  <LinearProgress
                    color="primary"
                    variant="determinate"
                    value={progress}
                  />
                )}
              </Grid>
              <Grid item xs={12} md={6} lg={4}>
                <Typography variant="overline">
                  Create an empty file...
                </Typography>
                <TextField
                  error={error.key === "name"}
                  helperText={
                    error.key === "name" &&
                    (error.value || "Insert a valid name")
                  }
                  variant="outlined"
                  value={name}
                  variant="outlined"
                  value={name}
                  fullWidth
                  onChange={(e) => setName(e.target.value)}
                  placeholder="Name"
                />
                <Select
                  labelId="demo-simple-select-helper-label"
                  id="demo-simple-select-helper"
                  value={mimeType}
                  label="File type"
                  onChange={handleChange}
                  fullWidth
                  sx={{ mt: 2 }}
                >
                  {Object.keys(documentTypes).map((key) => {
                    return (
                      <MenuItem value={documentTypes[key].value}>
                        <Avatar
                          src={documentTypes[key].icon}
                          sx={{ width: 24, height: 24, mr: 2 }}
                        />
                        {documentTypes[key].label}
                      </MenuItem>
                    );
                  })}
                </Select>
                <Button
                  disabled={loading}
                  fullWidth
                  variant="contained"
                  sx={{ mt: 2 }}
                  onClick={() =>
                    submit({
                      mime_type: mimeType,
                      name,
                    })
                  }
                >
                  Create resource
                </Button>
              </Grid>
              <Grid item xs={12} md={6} lg={4}>
                <Typography variant="overline">
                  GENERATE A NEW FILE FROM GOOGLE DRIVE LINK
                </Typography>
                <TextField
                  error={error.key === "uri"}
                  helperText={
                    error.key === "uri" && (error.value || "Insert a valid uri")
                  }
                  variant="outlined"
                  value={uri}
                  fullWidth
                  onChange={(e) => setUri(e.target.value)}
                  placeholder="URI"
                />

                <Button
                  disabled={loading || !getIdFromUrl(uri)}
                  fullWidth
                  variant="contained"
                  sx={{ mt: 2 }}
                  onClick={() => submit(getIdFromUrl(uri)[0], true)}
                >
                  Import
                </Button>
              </Grid>
            </Grid>
          </Box>
        )}
      </div>
    </Container>
  );
}

ReactDOM.render(
  <ThemeProvider theme={theme}>
    {/* CssBaseline kickstart an elegant, consistent, and simple baseline to build upon. */}
    <CssBaseline />
    <App />
  </ThemeProvider>,
  document.querySelector("#root")
);
