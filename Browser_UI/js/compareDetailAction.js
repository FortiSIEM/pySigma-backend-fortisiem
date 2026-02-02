let allItems = [];
let currentIndex = 0;
let dmp = new diff_match_patch();

async function loadDetail(index) {
    const item = allItems[index];
    await Promise.all([
        getRuleDetail("left", item.SigmaRuleId, item.OldRuleFileName),
        getRuleDetail("right", item.SigmaRuleId, item.NewRuleFileName),
        getSigmaDetail("sigmaDetail", item.NewSigmaFileName)
    ]);
    document.getElementById("sigmaRuleId").textContent = item.SigmaRuleId;
    document.getElementById("newSigmaRuleFile").textContent = item.NewSigmaFileName;
    document.getElementById("oldSigmaRuleFile").textContent = item.OldSigmaFileName;
    document.getElementById("newRuleFile").textContent = item.NewRuleFileName;
    highlightDiff();
}

function updateButtonState() {
    document.getElementById("prevBtn").disabled =
        currentIndex === 0;

    document.getElementById("nextBtn").disabled =
        currentIndex === allItems.length - 1;
}

function receiveData(params) {
    currentIndex = params.index;
    allItems = params.items;
    loadDetail(currentIndex);
    updateButtonState()
}


function prevItem() {
  if (currentIndex > 0) {
        currentIndex--;
        loadDetail(currentIndex);
        updateButtonState();
   }
}

function nextItem() {
   if (currentIndex < allItems.length - 1) {
        currentIndex++;
        loadDetail(currentIndex);
        updateButtonState();
   }
}

function getSigmaDetail(elemId, newSigmaFileName) {
  const url_header = getUrlHeader();
  const URL =
    `${url_header}/query_sigma_rule?` +
    `sigma_rule_file=${encodeURIComponent(newSigmaFileName)}`;

  const elem = document.getElementById(elemId);

  return fetch(URL)
    .then(res => {
      if (!res.ok) {
        throw new Error(`HTTP ${res.status}: ${res.statusText}`);
      }
      return res.text();
    })
    .then(text => {
      elem.textContent = text || "File is empty";
    })
    .catch(err => {
      elem.textContent = "Failed to load Sigma rule";
      console.error(err);
    });
}

function getRuleDetail(elemId, sigmaRuleId, ruleFile) {
  const url_header = getUrlHeader();
  const URL =
    `${url_header}/query_rule?` +
    `sigma_rule_Id=${encodeURIComponent(sigmaRuleId)}` +
    `&rule_file=${encodeURIComponent(ruleFile)}`;

  const elem = document.getElementById(elemId)
  return fetch(`${URL}`)
    .then(res => res.json())
    .then(res => {
      if (res.code !== 0) {
	elem.innerText = res.errMsg
      }
      elem.innerText = res.rule
    });
}

function selectedRight() {
   const rightText = document.getElementById("right").innerText;
   const sigmaRuleId = document.getElementById("sigmaRuleId").textContent;
   const newRuleFile = document.getElementById("newRuleFile").textContent;
  
   updateRule("right", sigmaRuleId, newRuleFile);
}

function selectedLeft() {
   const rightText = document.getElementById("right").innerText;
   const sigmaRuleId = document.getElementById("sigmaRuleId").textContent;
   const newRuleFile = document.getElementById("newRuleFile").textContent;
  
   updateRule("left", sigmaRuleId, newRuleFile);

}

function updateRule(elemId, sigmaRuleId, newRuleFile) {
  const leftText = document.getElementById(elemId).innerText;

  const formData = new FormData();
  formData.append("rule_xml", leftText);
  formData.append("sigma_rule_Id", sigmaRuleId);
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


function highlightDiff() {
    const leftText = document.getElementById("left").innerText;
    const rightText = document.getElementById("right").innerText;

    const diffs = dmp.diff_main(leftText, rightText);
    dmp.diff_cleanupSemantic(diffs);

    document.getElementById("left").innerHTML = renderDiff(diffs, -1);
    document.getElementById("right").innerHTML = renderDiff(diffs, 1);
}

function renderDiff(diffs, side) {
    return diffs.map(d => {
        const [op, text] = d;
        if (op === 0) return escapeHtml(text);
	if (side === -1 && op === -1) {
            return `<span class="del">${escapeHtml(text)}</span>`;
        }

        if (side === 1 && op === 1) {
            return `<span class="add">${escapeHtml(text)}</span>`;
        }

        return "";
    }).join("");
}

function escapeHtml(str) {
    return str.replace(/[&<>"']/g, m => ({
        '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'
    }[m]));
}

function quit() {
  window.close();
}
