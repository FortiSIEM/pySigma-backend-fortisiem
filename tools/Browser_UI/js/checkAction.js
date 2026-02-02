function receiveData(item) {
    if (item.ruleFile) {
        document.getElementById("RuleFile").value = item.ruleFile;
    }
    if (item.fileType) {
        document.getElementById("RuleFileType").value = item.fileType;
    }
    if (item.CommitId) {
        document.getElementById("commitId").value = item.CommitId;
    } 
    getRuleFileList();
    refresh();
}


function getRuleFileList() {
  const url_header = getUrlHeader();
  const URL = `${url_header}/query_file_list?`

  fetch(`${URL}`)
    .then(res => res.json())
    .then(res => {
      if (res.code !== 0) {
        alert(res.errMsg);
        return;
      }

      if (!res.fileLists || res.fileLists.length === 0) {
        return;
      }

      for (const filename of res.fileLists) {
        updateRuleFileList(filename, "add");
      }

    });
}

function refresh() {
   const ruleFileName = document.getElementById("RuleFile").value.trim();
   const ruleFileType = document.getElementById("RuleFileType").value.trim();
   const commitId = document.getElementById("commitId").value.trim();
   if (ruleFileName ==="") {
      alert("Please select a rule file");
      return;
   }
   if (ruleFileType=== "error") {
     showErrRules(ruleFileName, commitId)
   } else {
     getAllRulesDetail(ruleFileName, commitId);
   }
}



function clearTable() {
   const tbody = document.getElementById("checkTableBody");
   tbody.innerHTML = "";
   return;
}

function downloadRule() {
 let url_header = getUrlHeader();
 const ruleFileName = document.getElementById("RuleFile").value.trim();
 URL = url_header + "/download/" + ruleFileName;
 window.open(URL);
}

function showErrRules(ruleFileName, commitId){
 let url_header = getUrlHeader();
 const URL = url_header + "/view/" + ruleFileName + "?sigma_commitId=" + commitId;
 fetch(`${URL}`)
    .then(res => res.json())
    .then(res => {
      if (res.code !== 0) {
	alert(`Failed to get error rules  detail: ${res.code}\nError: ${res.errMsg}`)
        return;
      }

      if (!res.rules || res.rules.length === 0) {
	 alert("No Rule Converted Failed")

         return;
      }

      const tbody = document.getElementById("checkTableBody");
      tbody.innerHTML = "";
      const tr = document.createElement("tr");
      const tdSigma = document.createElement("td");
      tdSigma.textContent = "Sigma Rule";
      const tdErrMsg = document.createElement("td");
      tdErrMsg.textContent = "Error Message"
      const tdSingleEvtConstr = document.createElement("td");
      tdSingleEvtConstr.textContent = "SingleEvtConstr"
      tr.appendChild(tdSigma);
      tr.appendChild(tdErrMsg);
      tr.appendChild(tdSingleEvtConstr);
      tbody.appendChild(tr);

      res.rules.forEach(item => {
        const tr = document.createElement("tr");

        const tdSigmaRule = document.createElement("td");
        tdSigmaRule.textContent = item.SigmaRule;
	tdSigmaRule.className = "sigma";

        const tdErr = document.createElement("td");
        tdErr.textContent = item.ErrMsg;

        const tdConstr = document.createElement("td");
        tdConstr.textContent = item.SingleEvtConstr;
	tdConstr.className = "forti"
	//tdConstr.contentEditable = "true";

        tr.appendChild(tdSigmaRule);
        tr.appendChild(tdErr);
        tr.appendChild(tdConstr);
        tbody.appendChild(tr);
        return;
      });

    });
}

function getAllRulesDetail(ruleFileName, commitId){
  const url_header = getUrlHeader();
  const URL =
    `${url_header}/rules_detail?` +
    `&rule_file=${encodeURIComponent(ruleFileName)}` +
    `&sigma_commitId=${encodeURIComponent(commitId)}`;

  fetch(`${URL}`)
    .then(res => res.json())
    .then(res => {
      if (res.code !== 0) {
	alert(`Failed to get rules detail: ${res.code}\nError: ${res.errMsg}`)
	return;
      }

      const rules = res.rules;
      const tbody = document.getElementById("checkTableBody");
      tbody.innerHTML = "";

      rules.forEach((item, index) => {
          const tr = document.createElement("tr");

          const sigmaTd = document.createElement("td");
          sigmaTd.className = "sigma";
          sigmaTd.textContent = item[0];

          const fortiActionTd = document.createElement("td");

          const fortiTd = document.createElement("div");
          fortiTd.className = "forti";
          fortiTd.contentEditable = "true";
          fortiTd.textContent = item[1];

          const btn = document.createElement("button");
          btn.textContent = "Save";
          btn.style.marginTop = "5px";
          btn.onclick = () => saveRule(btn, index);

          fortiActionTd.appendChild(fortiTd);
          fortiActionTd.appendChild(btn);

          tr.appendChild(sigmaTd);
          tr.appendChild(fortiActionTd);

          tbody.appendChild(tr);
      });
  });
}

function saveRule(button, index) {
  const row = button.closest("tr");
  const fortiCell = row.querySelector(".forti");
  const ruleFileName = document.getElementById("RuleFile").value.trim();

  const fortiText = fortiCell.innerText.trim();
  const formData = new FormData();
  formData.append("rule_xml", fortiText);
  formData.append("rule_file", ruleFileName);
  const URL =  getUrlHeader() + "/update_rule";
  fetch(URL, {
    method: "POST",
    body: formData
  })
  .then(response => response.json())
  .then(data => {
    if(data.code === 0) {
       alert(`Save successfully`);
     } else {
       alert(`Failed to save: ${data.errMsg}`);
     }
  })
  .catch(err => {
    alert(`Failed to save: ${err}`);
  });
}

function quit() {
  window.close();
}

function openFileChooser() {
  document.getElementById("selectedRuleXml").click();
}

function clearSelectedFile() {
  const fileInput = document.getElementById("selectedRuleXml");
  fileInput.value = "";
  const ruleFileElem = document.getElementById("RuleFile");
  ruleFileElem.value = "";
  document.getElementById("log").textContent = "";
  clearTable();
}

function onRuleXmlChange() {
  const fileInput = document.getElementById("selectedRuleXml");
  if (fileInput.files.length !== 0) {
    uploadRuleXml();
  }
}

async function uploadRuleXml() {
  const fileInput = document.getElementById("selectedRuleXml");
  if (fileInput.files.length === 0) {
    alert(`Please select a rule XML file`);
    return;
  }

  const file = fileInput.files[0];
  const hostname = window.location.hostname;
  const URL = "ws://" + hostname + ":8765";

  const response = await uploadFileViaWS(file, URL, 15000);
  if (response.success) {
    const ackData = response.data;
    document.getElementById("RuleFile").value = ackData.filename;
    updateRuleFileList(ackData.filename, 'add');
    document.getElementById("log").textContent = "Rule uploaded to server tmp: " + ackData.filename;
    refresh();
  } else {
    const errorData = response.data;
    document.getElementById("log").textContent = "Upload failed: " + errorData.message;
    alert(`Upload failed: ${errorData.message}`);
  }
}

function updateRuleFileList(value, action) {
  let datalist;
  if (value.endsWith(".csv")) {
     datalist = document.getElementById('eventTypeFileList');
  } else {
     datalist = document.getElementById('ruleFileList');
  }
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
