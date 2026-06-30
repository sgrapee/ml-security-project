const child_process = require("child_process");

function runCommand(userInput) {
  child_process.exec("ping " + userInput);
}

function renderComment(comment) {
  document.getElementById("result").innerHTML = comment;
}
