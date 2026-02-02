function getUrlHeader() {
  const hostname = window.location.hostname;
  let server = hostname +":7777";
  let url_header = "http://" + server;
  return url_header;
}


