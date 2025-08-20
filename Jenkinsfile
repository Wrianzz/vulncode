def lib = library(
  identifier: 'devsecops-lib@main',
  retriever: modernSCM([
    $class: 'GitSCMSource',
    remote: 'https://github.com/Wrianzz/devsecops-lib.git', 
  ])
)

devsecopsCi([
    gitUrl: 'https://github.com/Wrianzz/vulncode.git',
    dd: [
        productName : 'DevSecOps',
        engagementName: 'Vulnerable-Code',
        url : 'http://192.168.88.20:8280',
        credsId : 'defectdojo-api-key',
        sourceCodeUrl : 'https://github.com/Wrianzz/vulncode.git'
    ],
    docker: [
        imageNameBase: 'my-app'
    ],
    sonar: [
        projectKey : 'vulnerable-code',
        hostUrl : 'http://192.168.88.20:9000',
        scannerTool : 'sonarqube', 
        tokenCredsId : 'sonarqube-token'
    ],
    mainBranches: ['master','main','production'],

    verifiedPolicy: [
        'Trufflehog Scan': true,
        'Anchore Grype' : false,
        'Trivy Scan' : false,
        'SonarQube Scan' : false
    ]
])
