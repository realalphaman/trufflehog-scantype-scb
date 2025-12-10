async function parse(scanResults) {

  if (typeof(scanResults) === "string") // empty file
    return [];
    
  const findings = [];

  for (let i = 0; i < scanResults.matches.length; i++) {
      findings.push({
          name: "trufflehog scan secret: " + scanResults.matches[i].DetectorName,
          description: scanResults.matches[i].DetectorDescription,
          category: "trufflehog scan secret",
          location: scanResults.matches[i].SourceMetadata.Data.Git.repository + "/blob/" + scanResults.matches[i].SourceMetadata.Data.Git.commit + "/" + scanResults.matches[i].SourceMetadata.Data.Git.file + "#L" + scanResults.matches[i].SourceMetadata.Data.Git.line,
          osi_layer: "APPLICATION",
          severity: "HIGH",
          reference: {},
          confidence: scanResults.matches[i].SourceMetadata.Data.Git.Raw,
          attributes: {}
      })
    }
    
  return findings;
}

module.exports.parse = parse;