function receiveData(item) {
    document.getElementById("RuleFile").textContent = item.ruleFile;
    document.getElementById("RuleFileType").textContent = item.fileType;
    refresh();
}


function refresh() {
   const ruleFileName = document.getElementById("RuleFile").textContent.trim();
   const ruleFileType = document.getElementById("RuleFileType").textContent.trim();
   if (ruleFileName ==="") {
      document.getElementById("log").textContent = "Please slect a rule file";
      return;
   }
   if (ruleFileType=== "error") {
     showErrRules(ruleFileName)
   } else {
     getAllRulesDetail(ruleFileName); 
   }
}



function clearTable() {
   const tbody = document.getElementById("checkTableBody");
   tbody.innerHTML = "";
   return;
}

function showErrRules(ruleFileName){
 let url_header = getUrlHeader();
 URL = url_header + "/view/" + ruleFileName;
 fetch(`${URL}`)
    .then(res => res.json())
    .then(res => {
      if (res.code !== 0) {
        alert(res.errMsg);
        return;
      }

      if (!res.rules || res.rules.length === 0) {
         document.getElementById("log").textContent = "No Rule Converted Failed";
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

function getAllRulesDetail(ruleFileName){
  const url_header = getUrlHeader();
  const URL =
    `${url_header}/rules_detail?` +
    `&rule_file=${encodeURIComponent(ruleFileName)}`;

  fetch(`${URL}`)
    .then(res => res.json())
    .then(res => {
      if (res.code !== 0) {
	document.getElementById("log").textContent = `Failed to get rules detail: ${res.code}\nError: ${res.errMsg}\n`;
	return;
      }

      rules = res.rules;
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
  const newRuleFile = document.getElementById("newRuleFile").textContent;

  const fortiText = fortiCell.innerText.trim();
  const formData = new FormData();
  formData.append("rule_xml", fortiText);
  formData.append("rule_file", newRuleFile);
  const URL =  getUrlHeader() + "/update_rule";
  fetch(URL, {
    method: "POST",
    body: formData
  })
  .then(response => response.json())
  .then(data => {
    if(data.code === 0) {
       document.getElementById("log").textContent = "Save successfully";
     } else {
       document.getElementById("log").textContent = `Error Code: ${data.code}\nError: ${data.errMsg}\n`;
     }
  })
  .catch(err => {
    document.getElementById("log").textContent = "Fetch error: " + err;
  });
}

function quit() {
  window.close();
}
