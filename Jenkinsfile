pipeline {
    agent any

    environment {
        CLIENT_ID = '123e4567-e89b-12d3-a456-426614174001'
        CLIENT_SECRET = '7a91d1c9-2583-4ef6-8907-7c974f1d6a0e'
        APPLICATION_ID = '673413da502d06461c39d283'
        SCA_API_URL = 'https://appsecops-api.intruceptlabs.com/api/v1/integrations/sca-scans'
        SAST_API_URL = 'https://appsecops-api.intruceptlabs.com/api/v1/integrations/sast-scans'
    }

    stages {
        stage('Clean Up Old Files') {
            steps {
                script {
                    sh 'rm -rf venv'
                    sh 'rm -rf project.zip'
                    sh 'rm -rf *.json'
                    sh 'rm -rf *.csv'
                    sh 'rm -rf *.sh'
                }
            }
        }

        stage('Checkout Code') {
            steps {
                checkout scm
            }
        }

        stage('Create ZIP Files') {
            steps {
                script {
                    sh 'rm -rf project_folder'
                    sh 'mkdir project_folder'
                    sh 'find . -maxdepth 1 -not -name "." -not -name ".." -not -name ".git" -not -name "venv" -not -name "project_folder" -exec mv {} project_folder/ \\;'
                    sh 'zip -r project.zip project_folder'
                }
            }
        }

        stage('Perform SCA Scan') {
            steps {
                script {
                    def response = sh(script: """
                        #!/bin/bash
                        curl -v -X POST \
                        -H "Client-ID: ${CLIENT_ID}" \
                        -H "Client-Secret: ${CLIENT_SECRET}" \
                        -F "projectZipFile=@project.zip" \
                        -F "applicationId=${APPLICATION_ID}" \
                        -F "scanName=Vulnado-JAVA SCA Scan" \
                        -F "language=java" \
                        "${SCA_API_URL}"
                    """, returnStdout: true).trim()

                    def jsonResponse = readJSON(text: response)
                    def canProceedSCA = jsonResponse.canProceed
                    def vulnsTable = jsonResponse.vulnsTable

                    def cleanVulnsTable = vulnsTable.replaceAll(/\x1B\[[;0-9]*m/, '')

                    echo "Vulnerabilities found during SCA:"
                    echo "${cleanVulnsTable}"

                    env.CAN_PROCEED_SCA = canProceedSCA.toString()
                }
            }
        }

        stage('Perform SAST Scan') {
            when {
                expression { return env.CAN_PROCEED_SCA == 'true' }
            }
            steps {
                script {
                    def response = sh(script: """
                        #!/bin/bash
                        curl -v -X POST \
                        -H "Client-ID: ${CLIENT_ID}" \
                        -H "Client-Secret: ${CLIENT_SECRET}" \
                        -F "projectZipFile=@project.zip" \
                        -F "applicationId=${APPLICATION_ID}" \
                        -F "scanName=Vulnado-JAVA SAST Scan" \
                        -F "language=java" \
                        "${SAST_API_URL}"
                    """, returnStdout: true).trim()

                    def jsonResponse = readJSON(text: response)
                    def canProceedSAST = jsonResponse.canProceed
                    def vulnsTable = jsonResponse.vulnsTable

                    def cleanVulnsTable = vulnsTable.replaceAll(/\x1B\[[;0-9]*m/, '')

                    echo "Vulnerabilities found during SAST:"
                    echo "${cleanVulnsTable}"

                    env.CAN_PROCEED_SAST = canProceedSAST.toString()
                }
            }
        }

        // Additional stages (e.g., deploy) can be added here
    }
}
