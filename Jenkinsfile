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
                    sh 'rm -rf venv project.zip project_folder *.json *.csv *.sh'
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
                    sh '''
                        rm -rf project_folder
                        mkdir project_folder
                        find . -maxdepth 1 -not -name "." -not -name ".." -not -name ".git" -not -name "venv" -not -name "project_folder" -exec mv {} project_folder/ \\;
                        zip -r project.zip project_folder
                    '''
                }
            }
        }

        stage('Perform SCA Scan') {
            steps {
                script {
                    def response = sh(script: """
                        #!/bin/bash
                        curl -s -w "%{http_code}" -X POST \
                        -H "Client-ID: ${CLIENT_ID}" \
                        -H "Client-Secret: ${CLIENT_SECRET}" \
                        -F "projectZipFile=@project.zip" \
                        -F "applicationId=${APPLICATION_ID}" \
                        -F "scanName=New SCA Scan from Jenkins Pipeline" \
                        -F "language=java" \
                        "${SCA_API_URL}" \
                        -o sca_response.json
                    """, returnStdout: true).trim()

                    def httpCode = response[-3..-1]  // Extract last 3 characters for HTTP code
                    def jsonResponse = readJSON(file: 'sca_response.json')

                    if (httpCode != "200") {
                        error "SCA scan failed with HTTP code ${httpCode}: ${jsonResponse?.message}"
                    }

                    def vulnsTable = jsonResponse.vulnsTable ?: "No vulnerabilities found."
                    def canProceedSCA = jsonResponse.canProceed ?: false

                    echo "Vulnerabilities found during SCA:"
                    echo vulnsTable

                    env.CAN_PROCEED_SCA = canProceedSCA.toString()
                }
            }
        }

        stage('Check SCA Result') {
            when {
                expression { return env.CAN_PROCEED_SCA != 'true' }
            }
            steps {
                error "SCA scan failed. Deployment cancelled."
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
                        curl -s -w "%{http_code}" -X POST \
                        -H "Client-ID: ${CLIENT_ID}" \
                        -H "Client-Secret: ${CLIENT_SECRET}" \
                        -F "projectZipFile=@project.zip" \
                        -F "applicationId=${APPLICATION_ID}" \
                        -F "scanName=New SAST Scan from Jenkins Pipeline" \
                        -F "language=java" \
                        "${SAST_API_URL}" \
                        -o sast_response.json
                    """, returnStdout: true).trim()

                    def httpCode = response[-3..-1]
                    def jsonResponse = readJSON(file: 'sast_response.json')

                    if (httpCode != "200") {
                        error "SAST scan failed with HTTP code ${httpCode}: ${jsonResponse?.message}"
                    }

                    def vulnsTable = jsonResponse.vulnsTable ?: "No vulnerabilities found."
                    def canProceedSAST = jsonResponse.canProceed ?: false

                    echo "Vulnerabilities found during SAST:"
                    echo vulnsTable

                    env.CAN_PROCEED_SAST = canProceedSAST.toString()
                }
            }
        }

        stage('Check SAST Result') {
            when {
                expression { return env.CAN_PROCEED_SAST != 'true' }
            }
            steps {
                error "SAST scan failed. Deployment cancelled."
            }
        }

        stage('Set Up Python') {
            steps {
                sh '''
                    python3 -m venv venv
                    . venv/bin/activate && pip install --upgrade pip
                '''
            }
        }

        stage('Install Dependencies') {
            steps {
                sh '. venv/bin/activate && pip install -r requirements.txt'
            }
        }

        // Additional stages (e.g., deploy) can be added here
    }
}
