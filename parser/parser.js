const repoUrlAnnotationKey = "metadata.scan.securecodebox.io/git-repo-url";

export async function parse(fileContent, scan) {
  if (!fileContent) {
    return [];
  }

  const report = JSON.parse(fileContent);
  console.log("Hello from the console!");
  console.log(report);

  if (!report) {
    return [];
  }

  


  return report.map((finding) => {
    let severity = "MEDIUM";
    console.log("zzzz");

    
    return {
      name: "trufflehog scan secret: " + finding.DetectorName,
      description:
        finding.DetectorDescription,
      osi_layer: "APPLICATION",
      severity: severity,
      category: "Potential Secret",
      location: finding.SourceMetadata.Data.Git.repository + "/blob/" + finding.SourceMetadata.Data.Git.commit + "/" + finding.SourceMetadata.Data.Git.file + "#L" + finding.SourceMetadata.Data.Git.line,
      osi_layer: "APPLICATION",
      severity: "HIGH",
      reference: {},
      confidence: finding.SourceMetadata.Data.Git.Raw,
      attributes: finding.SourceMetadata.Data.Git,
    };
  });
}

