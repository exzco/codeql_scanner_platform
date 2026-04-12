const result_sarif = Bun.file("./results.sarif")
const sarif_json = await result_sarif.json()

// console.log(sarif_json)
const runs = sarif_json.runs[0]

const tool = runs.tool
const tool_notifications = tool.driver.notifications
const tool_rules = tool.driver.rules
const tool_extensions = tool.extensions


const result = runs.results
const properties = runs.properties
const invocations = runs.invocations

const artifacts = runs.artifacts
console.dir(artifacts, { depth: null });
// console.dir(invocations, { depth: null });
// console.dir(properties, { depth: null });
// console.dir(result, { depth: null });
// tool_extensions.forEach(ext => {
//     console.dir(ext.locations, { depth: null });
// });

// console.log("================tool_notifications================")
// console.log(tool_notifications)
// console.log("================tool_rules================")
// console.log(tool_rules)
// console.log("================tool_extensions================")
// console.log(tool_extensions)

