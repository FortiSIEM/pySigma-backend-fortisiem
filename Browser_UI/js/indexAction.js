function clearTable() {
  const tbody = document.getElementById("resultTableBody");
  if (tbody) {
    tbody.innerHTML = "";
  }

  const container = document.getElementById("resultTableContainer");
  const clearErrTable = document.getElementById("clearTableBtn");
  if (container) {
    container.style.display = "none";
    clearErrTable.style.display = "none";
  }

}

function onRuleXmlChange() {
    const fileInput = document.getElementById("selectedRuleXml");
    if (fileInput.files.length !== 0) {
	uploadRuleXml();
    }
    
}

function clearSelectedFile() {
    const fileInput = document.getElementById("selectedRuleXml");
    fileInput.value = "";
    const oldRuleFileElem = document.getElementById("oldRuleFile");
    oldRuleFileElem.value = ""
    document.getElementById("log").textContent = "";
    onRuleXmlChange();
}

function startUpdate() {
  const cloneUrl = document.getElementById("cloneUrl").value;
  const sigmaPath = document.getElementById("sigmaPath").value;
  const commitId = document.getElementById("commitId").value;
  const oldCommitId = document.getElementById("oldCommitId").value;
  const newRuleStart = document.getElementById("newRuleStart").value;

  const fileInput = document.getElementById("selectedRuleXml");
  const formData = new FormData();
  const updateActionElem = document.getElementById("updateAction");
  formData.append("clone_url", cloneUrl);
  formData.append("sigma_path", sigmaPath);
  formData.append("commit_id", commitId);
  formData.append("new_rule_start_index", newRuleStart);

  const logElem = document.getElementById("log");
  const ruleFileNameElem = document.getElementById("ruleFileName")
  const errorRuleStatusFileNameElem = document.getElementById("errorRuleStatusFileName")
  const oldRuleFileElem = document.getElementById("oldRuleFile");

  //ruleFileNameElem.value = "";
  //errorRuleStatusFileNameElem.value = "";
  clearTable()

  logElem.textContent = "Running...\n";
  let url_header = getUrlHeader();
  let URL = ""
  
  const ruleFileName = document.getElementById("oldRuleFile").value.trim();
  if (ruleFileName !== "") {
    formData.append("update_action", updateActionElem.value);
    formData.append("rule_file", ruleFileName);
    formData.append("old_commit_id", oldCommitId.value);
    formData.append("new_rule_filename", ruleFileNameElem.value);
    formData.append("error_rule_status_filename", errorRuleStatusFileName.value);
    URL =  url_header + "/update";
  } else {
    formData.append("update_action", "all");
    formData.append("new_rule_filename", ruleFileNameElem.value);
    formData.append("error_rule_status_filename", errorRuleStatusFileName.value);
    URL = url_header + "/new"
  }

  fetch(URL, {
    method: "POST",
    body: formData
  })
  .then(response => response.json())
  .then(data => {
    if(data.code === 0) {
       logElem.textContent = "Converted successfully";
       ruleFileNameElem.value = data.NewRuleFileName;
       errorRuleStatusFileNameElem.value = data.ErrRuleFileName;
       updateRuleFileList(data.NewRuleFileName, "add")
       updateRuleFileList(data.ErrRuleFileName, "add")
     } else {
       logElem.textContent = `Error Code: ${data.code}\nError: ${data.errMsg}\n`;
     }
  })
  .catch(err => {
    document.getElementById("log").textContent = "Fetch error: " + err;
  });
}

function openFileChooser() {
  document.getElementById("selectedRuleXml").click();
}

function waitForAck(ws, timeout = 10000) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error("Timeout waiting for ACK")), timeout);

    ws.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        if (data.type === "ack") {
          clearTimeout(timer);
          resolve({ success: true, data });
        } else if (data.type === "error") {
          clearTimeout(timer);
          resolve({ success: false, data });
        }
      } catch {}
    };

    ws.onerror = (e) => {
      clearTimeout(timer);
      reject(new Error("WebSocket error"));
    };
    ws.onclose = (e) => {
      clearTimeout(timer);
      reject(new Error("WebSocket closed"));
    };
  });
}

function getRuleFileList() {
  const url_header = getUrlHeader();
  const URL = `${url_header}/query_rule_file_list?`

  fetch(`${URL}`)
    .then(res => res.json())
    .then(res => {
      if (res.code !== 0) {
        alert(res.errMsg);
        return;
      }

      if (!res.ruleFileLists || res.ruleFileLists.length === 0) {
         return;
      }
      const datalist = document.getElementById('ruleFileList');
      datalist.innerHTML = ''; 
      res.ruleFileLists.forEach(item => {
	  const option = document.createElement('option');
          option.value = item;
          datalist.appendChild(option);
      });
    });
}


function updateRuleFileList(value, action) {
  const datalist = document.getElementById('ruleFileList');
  const options = datalist.getElementsByTagName('option');
  if (action == "add") {
    const valueExists = Array.from(options).some(option => option.value === value);
    if (valueExists) {
       return;
    }
    const option = document.createElement('option');
    option.value = value;
    datalist.appendChild(option);
  } else if (action == "del") {
    for (let i = options.length - 1; i >= 0; i--) {
      if (options[i].value === value) {
        datalist.removeChild(options[i]);
      }
    }
  }
}

async function uploadRuleXml() {
  const fileInput = document.getElementById("selectedRuleXml");
  if (fileInput.files.length === 0) {
    alert("Please select a rule XML file");
    return;
  }

  const file = fileInput.files[0];
  const hostname = window.location.hostname;
  const URL = "ws://" + hostname + ":8765";

  const response = await uploadFileViaWS(file, URL, 15000);
  if (response.success) {
        const ackData = response.data;
        document.getElementById("oldRuleFile").value = ackData.filename;
	updateRuleFileList(ackData.filename, 'add')
        document.getElementById("ruleText").textContent = "Update Selected Rule File";
        document.getElementById("log").textContent =
          "Rule uploaded to server tmp: " + ackData.filename;
  } else {
        const errorData = response.data;
        document.getElementById("log").textContent =
          "Upload failed: " + errorData.message;
  }
}

function showInBrowser() {
 let url_header = getUrlHeader();
 const ruleFileName = document.getElementById("ruleFileName").value;		
 URL = url_header + "/open/" + ruleFileName;
 window.open(URL);
}

function downloadRule() {
 let url_header = getUrlHeader();
 const ruleFileName = document.getElementById("ruleFileName").value;		
 URL = url_header + "/download/" + ruleFileName;
 window.open(URL);
}

function showErrRules() {
   const errFileName = document.getElementById("errorRuleStatusFileName").value.trim();
  if (!errFileName) {
    document.getElementById("log").textContent = "No Rule Converted Failed File";
    return;
  }

  const win = window.open("checkRule.html", "_blank", "width=1000,height=600");
  const currentItem = {"ruleFile": errFileName, "fileType": "error"}
  win.onload = function () {
      if (typeof win.receiveData === "function") {
         win.receiveData(currentItem);
      } else {
         console.error("receiveData function not found in checkRule.html");
      }
  };

}

function checkRules() {
  const newRuleFileName = document
    .getElementById("ruleFileName")
    .value
    .trim();


  if (!newRuleFileName) {
    document.getElementById("log").textContent = "No new rule file";
    return;
  }

  const win = window.open("checkRule.html", "_blank", "width=1400,height=800");
  const currentItem = {"ruleFile": newRuleFileName, "fileType": "rule"}
  win.onload = function () {
      if (typeof win.receiveData === "function") {
         win.receiveData(currentItem);
      } else {
         console.error("receiveData function not found in checkRule.html");
      }
  };

}

function compareRules() {
  const newRuleFileName = document.getElementById("ruleFileName").value.trim();
  const oldRuleFileName = document.getElementById("oldRuleFile").value.trim(); 
  const commitId = document.getElementById("commitId").value.trim();

  if (!newRuleFileName) {
    document.getElementById("log").textContent = "No new rule file";
    return;
  }
  if (!oldRuleFileName) {
    document.getElementById("log").textContent = "No old rule file";
    return;
  }

  const win = window.open("compare.html", "_blank", "width=1400,height=800");
  const currentItem = {"NewRuleFileName": newRuleFileName,
                       "OldRuleFileName": oldRuleFileName,
                       "CommitId": commitId}
  win.onload = function () {
      if (typeof win.receiveData === "function") {
         win.receiveData(currentItem);
      } else {
         console.error("receiveData function not found in compare.html");
      }
  };

}

function quit() {
  window.close();
}

