function UpdateRules() {
  const newRuleFileName = "" 
  const win = window.open("updateRule.html", "_blank", "width=800,height=800");
  const currentItem = {"ruleFile": newRuleFileName, "fileType": "rule"}
  win.onload = function () {
      if (typeof win.receiveData === "function") {
         win.receiveData(currentItem);
      } else {
         console.error("receiveData function not found in updateRule.html");
      }
  };

}

function checkRules() {
  const newRuleFileName = "" 

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
  const newRuleFileName = "" 
  const oldRuleFileName = "" 
  const commitId = ""

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

