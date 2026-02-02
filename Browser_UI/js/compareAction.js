function receiveData(item) {
    document.getElementById("newRuleFile").textContent = item.NewRuleFileName;
    document.getElementById("oldRuleFile").textContent = item.OldRuleFileName;
    refreshTable();
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
  const newRuleFileName = document.getElementById("newRuleFile").textContent.trim(); 
  const oldRuleFileName = document.getElementById("oldRuleFile").textContent.trim();
  
  if (newRuleFileName === "") {
      document.getElementById("log").textContent = "Please select a new rule file";
      return;
  }
  if (oldRuleFileName === "") {
      document.getElementById("log").textContent = "Please select an old rule file";
      return;
  }
  compareRules(newRuleFileName, oldRuleFileName) 
}

function compareRules(newRuleFileName, oldRuleFileName) {
  const url_header = getUrlHeader();
  if (!newRuleFileName) {
    document.getElementById("log").textContent = "No new rule file";
    return;
  }

  if (!oldRuleFileName) {
    document.getElementById("log").textContent = "No old rule file";
    return;
  }

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
                     index: i
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

function quit() {
  window.close();
}

