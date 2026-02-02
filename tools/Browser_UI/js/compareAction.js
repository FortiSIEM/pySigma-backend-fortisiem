function receiveData(item) {
    if (item.NewRuleFileName) {
        document.getElementById("newRuleFile").value = item.NewRuleFileName;
    }
    if (item.OldRuleFileName) {
        document.getElementById("oldRuleFile").value = item.OldRuleFileName;
    }
    if (item.CommitId) {
        document.getElementById("commitId").value = item.CommitId;
    }
    getRuleFileList();
    refreshTable();
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

function clearTable() {
  const tbody = document.getElementById("resultTableBody");
  if (tbody) {
    tbody.innerHTML = "";
  }
  document.getElementById("info").textContent = ""
}

function refreshTable() {
  clearTable();
  const newRuleFileName = document.getElementById("newRuleFile").value.trim();
  const oldRuleFileName = document.getElementById("oldRuleFile").value.trim();
  
  if (newRuleFileName === "") {
      alert("Please select a new rule file")
      return;
  }
  if (oldRuleFileName === "") {
      alert("Please select a old rule file")
      return;
  }
  compareRules(newRuleFileName, oldRuleFileName) 
}

function compareRules(newRuleFileName, oldRuleFileName) {
  const url_header = getUrlHeader();
  if (!newRuleFileName) {
    alert("Please select a new rule file")
    return;
  }

  if (!oldRuleFileName) {
    alert("Please select a old rule file")
    return;
  }

  const commitId = document.getElementById("commitId").value.trim();

  const URL =
    `${url_header}/compare?` +
    `new=${encodeURIComponent(newRuleFileName)}` +
    `&old=${encodeURIComponent(oldRuleFileName)}`;

  fetch(`${URL}`)
    .then(res => res.json())
    .then(res => {
      if (res.code !== 0) {
        alert(res.errMsg);
        return;
      }
      document.getElementById("resultTableContainer").style.display  = "inline-block";
      document.getElementById("clearTableBtn").style.display  = "inline-block";
      document.getElementById("info").textContent = `Number of Modified Rule: ${res.modifiedNum}, Number of No Changed Rule:${res.noChangeNum}`

      const tbody = document.getElementById("resultTableBody");
      tbody.innerHTML = "";
      const tr = document.createElement("tr");
      const tdUpdateStatus = document.createElement("td");
      tdUpdateStatus.textContent = "Update Status";
      const tdOldRuleInfo = document.createElement("td");
      tdOldRuleInfo.textContent = "Old Rule Info"
      const tdNewRuleInfo = document.createElement("td");
      tdNewRuleInfo.textContent = "New Rule Info"

      tr.appendChild(tdUpdateStatus);
      tr.appendChild(tdOldRuleInfo);
      tr.appendChild(tdNewRuleInfo);
      tbody.appendChild(tr);

      res.diff.forEach((item, i) => {
        const tr = document.createElement("tr");

        const tdStatus = document.createElement("td");
        tdStatus.textContent = item.UpdateStatus;
	tdStatus.innerHTML =
	  `${item.UpdateStatus}<br>`+
	  `<button id="btn_compareDetail_${i}" type="button">CompareDetail</button>`

        const tdOld = document.createElement("td");
	tdOld.innerHTML =
          `<b>Sigma Rule Id:</b> ${item.SigmaRuleId}<br>` +
          `<b>File:</b> ${item.OldSigmaFileName}<br>` +
           `<b>File:</b> ${item.OldRuleFileName }<br>` +
          `<b>RuleName:</b> ${item.OldRuleName}<br>`;
	  //`<b>Constraint:</b><br>${item.OldSingleEvtConstr}`;

        const tdNew = document.createElement("td");
	if (item.NewSigmaFileName != null) { 
	  tdNew.innerHTML =
            `<b>Sigma Rule Id:</b> ${item.SigmaRuleId}<br>` +
            `<b>File:</b> ${item.NewSigmaFileName }<br>` +
            `<b>File:</b> ${item.NewRuleFileName }<br>` +
            `<b>RuleName:</b> ${item.NewRuleName}<br>`;
            //`<b>Constraint:</b><br>${item.NewSingleEvtConstr}`;
        }
        tr.appendChild(tdStatus);
        tr.appendChild(tdOld);
        tr.appendChild(tdNew);
        tbody.appendChild(tr);

	const btn = document.getElementById(`btn_compareDetail_${i}`);
	btn.addEventListener("click", () => {
    		const win = window.open("compareDetail.html", "_blank", "width=1400,height=800");
    
    		// Create a closure to capture the current 'item'
		//const currentItem = item 
		const params = {
                     items: res.diff,
                     index: i,
		     sigmaCommitId: commitId
                }
    		win.onload = function () {
        		if (typeof win.receiveData === "function") {
            			win.receiveData(params);
        		} else {
            		console.error("receiveData function not found in compare.html");
        		}
    		};

        });

      });
    });
}

function openFileChooser(type) {
     if (type === 'old') {
       document.getElementById("selectedOldRuleXml").click();
     } else {
       document.getElementById("selectedNewRuleXml").click();
     }
   }

function clearSelectedFile(type) {
     if (type === 'old') {
       const fileInput = document.getElementById("selectedOldRuleXml");
       fileInput.value = "";
       document.getElementById("oldRuleFile").value = "";
     } else {
       const fileInput = document.getElementById("selectedNewRuleXml");
       fileInput.value = "";
       document.getElementById("newRuleFile").value = "";
     }
     document.getElementById("log").textContent = "";
     clearTable();
   }

function onRuleXmlChange(type) {
     if (type === 'old') {
       const fileInput = document.getElementById("selectedOldRuleXml");
       if (fileInput.files.length !== 0) {
         uploadRuleXml('old');
       }
     } else {
       const fileInput = document.getElementById("selectedNewRuleXml");
       if (fileInput.files.length !== 0) {
         uploadRuleXml('new');
       }
     }
}


async function uploadRuleXml(type) {
     let fileInput, inputElem;
     if (type === 'old') {
       fileInput = document.getElementById("selectedOldRuleXml");
       inputElem = document.getElementById("oldRuleFile");
     } else {
       fileInput = document.getElementById("selectedNewRuleXml");
       inputElem = document.getElementById("newRuleFile");
     }

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
       inputElem.value = ackData.filename;
       updateRuleFileList(ackData.filename, 'add');
       //document.getElementById("log").textContent = "Rule uploaded to server tmp: " + ackData.filename;
       alert("Updated Rule Successfully");
       
     } else {
       const errorData = response.data;
       alert(`Failed to upload: ${errorData.message}`)
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

function quit() {
  window.close();
}

