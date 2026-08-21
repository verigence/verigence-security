# Live Security auth-stage diagnostic

## Railway deployments
```json
[
  {
    "id": "79c3888c-6f4e-4746-9d70-e25ab8ba82ee",
    "status": "SUCCESS",
    "createdAt": "2026-08-21T13:36:28.842Z",
    "meta": {
      "image": "ghcr.io/verigence/verigence-security@sha256:1643557dcf02748cd5e0f82de70abcd6aec2b982d364acb8142b05f7e05b0ee8",
      "imageDigest": "sha256:1643557dcf02748cd5e0f82de70abcd6aec2b982d364acb8142b05f7e05b0ee8",
      "logsV2": true,
      "patchId": "c0baa5be-aa40-4e13-aa7d-379c884b4ab2",
      "reason": "deploy",
      "runtime": "V2",
      "serviceManifest": {
        "build": {
          "buildCommand": null,
          "buildEnvironment": "V3",
          "builder": "RAILPACK",
          "dockerfilePath": null,
          "nixpacksConfigPath": null,
          "nixpacksPlan": null,
          "watchPatterns": []
        },
        "deploy": {
          "cronSchedule": null,
          "drainingSeconds": null,
          "healthcheckPath": null,
          "healthcheckTimeout": null,
          "ipv6EgressEnabled": false,
          "limitOverride": null,
          "multiRegionConfig": {
            "sin": {
              "numReplicas": 1
            }
          },
          "numReplicas": 1,
          "overlapSeconds": null,
          "preDeployCommand": null,
          "region": null,
          "registryCredentials": null,
          "requiredMountPath": null,
          "restartPolicyMaxRetries": 10,
          "restartPolicyType": "ON_FAILURE",
          "runtime": "V2",
          "sleepApplication": false,
          "startCommand": null,
          "useLegacyStacker": false
        }
      },
      "volumeMounts": []
    }
  },
  {
    "id": "d3a07654-fb33-4948-96bc-3dff84c43db8",
    "status": "REMOVED",
    "createdAt": "2026-08-21T13:36:21.815Z",
    "meta": {
      "image": "ghcr.io/verigence/verigence-security@sha256:e69a903082c25e1dd721aa8d651a53f0cc96765bef16238f8679a063c8080c24",
      "imageDigest": "sha256:e69a903082c25e1dd721aa8d651a53f0cc96765bef16238f8679a063c8080c24",
      "logsV2": true,
      "patchId": "7bd1e5aa-577e-457e-b335-e25b3cbcfdce",
      "reason": "deploy",
      "runtime": "V2",
      "serviceManifest": {
        "build": {
          "buildCommand": null,
          "buildEnvironment": "V3",
          "builder": "RAILPACK",
          "dockerfilePath": null,
          "nixpacksConfigPath": null,
          "nixpacksPlan": null,
          "watchPatterns": []
        },
        "deploy": {
          "cronSchedule": null,
          "drainingSeconds": null,
          "healthcheckPath": null,
          "healthcheckTimeout": null,
          "ipv6EgressEnabled": false,
          "limitOverride": null,
          "multiRegionConfig": {
            "sin": {
              "numReplicas": 1
            }
          },
          "numReplicas": 1,
          "overlapSeconds": null,
          "preDeployCommand": null,
          "region": null,
          "registryCredentials": null,
          "requiredMountPath": null,
          "restartPolicyMaxRetries": 10,
          "restartPolicyType": "ON_FAILURE",
          "runtime": "V2",
          "sleepApplication": false,
          "startCommand": null,
          "useLegacyStacker": false
        }
      },
      "volumeMounts": []
    }
  },
  {
    "id": "e132c5ff-8f91-444e-99b7-7e5310a4d6ef",
    "status": "REMOVED",
    "createdAt": "2026-08-21T13:35:43.840Z",
    "meta": {
      "buildOnly": false,
      "configFile": "/railway.toml",
      "fileServiceManifest": {
        "build": {
          "builder": "DOCKERFILE",
          "dockerfilePath": "Dockerfile"
        },
        "deploy": {
          "healthcheckPath": "/health/ready",
          "healthcheckTimeout": 20,
          "restartPolicyMaxRetries": 5,
          "restartPolicyType": "ON_FAILURE"
        }
      },
      "imageDigest": "sha256:44f97b4320839d8f9b9a656310f4ebabe60c694f8ac9e626c54a55f30910f35f",
      "logsV2": true,
      "nixpacksProviders": [],
      "propertyFileMapping": {
        "build.builder": "$.build.builder",
        "build.dockerfilePath": "$.build.dockerfilePath",
        "deploy.healthcheckPath": "$.deploy.healthcheckPath",
        "deploy.healthcheckTimeout": "$.deploy.healthcheckTimeout",
        "deploy.restartPolicyMaxRetries": "$.deploy.restartPolicyMaxRetries",
        "deploy.restartPolicyType": "$.deploy.restartPolicyType"
      },
      "reason": "deploy",
      "rootDirectory": null,
      "runtime": "V2",
      "serviceManifest": {
        "build": {
          "buildCommand": null,
          "buildEnvironment": "V3",
          "builder": "DOCKERFILE",
          "dockerfilePath": "Dockerfile",
          "nixpacksConfigPath": null,
          "nixpacksPlan": null,
          "watchPatterns": []
        },
        "deploy": {
          "cronSchedule": null,
          "drainingSeconds": null,
          "healthcheckPath": "/health/ready",
          "healthcheckTimeout": 20,
          "ipv6EgressEnabled": false,
          "limitOverride": null,
          "multiRegionConfig": {
            "sin": {
              "numReplicas": 1
            }
          },
          "numReplicas": 1,
          "overlapSeconds": null,
          "preDeployCommand": null,
          "region": null,
          "registryCredentials": null,
          "requiredMountPath": null,
          "restartPolicyMaxRetries": 5,
          "restartPolicyType": "ON_FAILURE",
          "runtime": "V2",
          "sleepApplication": false,
          "startCommand": null,
          "useLegacyStacker": false
        }
      },
      "volumeMounts": []
    }
  },
  {
    "id": "b92dd1f1-073a-4cd6-8447-0ce5d4c54533",
    "status": "REMOVED",
    "createdAt": "2026-08-21T13:01:58.020Z",
    "meta": {
      "image": "ghcr.io/verigence/verigence-security@sha256:4fe53ededfd2a0583d43b230c469b3ef0bd51146764269a5e046506c06442635",
      "imageDigest": "sha256:4fe53ededfd2a0583d43b230c469b3ef0bd51146764269a5e046506c06442635",
      "logsV2": true,
      "patchId": "e8ba2551-84c3-4f14-aa53-90050325ac3f",
      "reason": "deploy",
      "runtime": "V2",
      "serviceManifest": {
        "build": {
          "buildCommand": null,
          "buildEnvironment": "V3",
          "builder": "RAILPACK",
          "dockerfilePath": null,
          "nixpacksConfigPath": null,
          "nixpacksPlan": null,
          "watchPatterns": []
        },
        "deploy": {
          "cronSchedule": null,
          "drainingSeconds": null,
          "healthcheckPath": null,
          "healthcheckTimeout": null,
          "ipv6EgressEnabled": false,
          "limitOverride": null,
          "multiRegionConfig": {
            "sin": {
              "numReplicas": 1
            }
          },
          "numReplicas": 1,
          "overlapSeconds": null,
          "preDeployCommand": null,
          "region": null,
          "registryCredentials": null,
          "requiredMountPath": null,
          "restartPolicyMaxRetries": 10,
          "restartPolicyType": "ON_FAILURE",
          "runtime": "V2",
          "sleepApplication": false,
          "startCommand": null,
          "useLegacyStacker": false
        }
      },
      "volumeMounts": []
    }
  },
  {
    "id": "5f3b7eda-5293-4f92-bac0-53f1309be870",
    "status": "REMOVED",
    "createdAt": "2026-08-21T13:01:51.440Z",
    "meta": {
      "buildOnly": false,
      "configFile": "/railway.toml",
      "fileServiceManifest": {
        "build": {
          "builder": "DOCKERFILE",
          "dockerfilePath": "Dockerfile"
        },
        "deploy": {
          "healthcheckPath": "/health/ready",
          "healthcheckTimeout": 20,
          "restartPolicyMaxRetries": 5,
          "restartPolicyType": "ON_FAILURE"
        }
      },
      "logsV2": true,
      "nixpacksProviders": [],
      "propertyFileMapping": {
        "build.builder": "$.build.builder",
        "build.dockerfilePath": "$.build.dockerfilePath",
        "deploy.healthcheckPath": "$.deploy.healthcheckPath",
        "deploy.healthcheckTimeout": "$.deploy.healthcheckTimeout",
        "deploy.restartPolicyMaxRetries": "$.deploy.restartPolicyMaxRetries",
        "deploy.restartPolicyType": "$.deploy.restartPolicyType"
      },
      "reason": "deploy",
      "rootDirectory": null,
      "runtime": "V2",
      "serviceManifest": {
        "build": {
          "buildCommand": null,
          "buildEnvironment": "V3",
          "builder": "DOCKERFILE",
          "dockerfilePath": "Dockerfile",
          "nixpacksConfigPath": null,
          "nixpacksPlan": null,
          "watchPatterns": []
        },
        "deploy": {
          "cronSchedule": null,
          "drainingSeconds": null,
          "healthcheckPath": "/health/ready",
          "healthcheckTimeout": 20,
          "ipv6EgressEnabled": false,
          "limitOverride": null,
          "multiRegionConfig": {
            "sin": {
              "numReplicas": 1
            }
          },
          "numReplicas": 1,
          "overlapSeconds": null,
          "preDeployCommand": null,
          "region": null,
          "registryCredentials": null,
          "requiredMountPath": null,
          "restartPolicyMaxRetries": 5,
          "restartPolicyType": "ON_FAILURE",
          "runtime": "V2",
          "sleepApplication": false,
          "startCommand": null,
          "useLegacyStacker": false
        }
      },
      "volumeMounts": []
    }
  },
  {
    "id": "e1e7ac26-34ec-4927-8cea-85ee72876a43",
    "status": "REMOVED",
    "createdAt": "2026-08-21T13:01:01.963Z",
    "meta": {
      "image": "ghcr.io/verigence/verigence-security@sha256:d205bb1fabd9d5e305419d396713b6740f464371713d8763b945e2dd46123a0c",
      "imageDigest": "sha256:d205bb1fabd9d5e305419d396713b6740f464371713d8763b945e2dd46123a0c",
      "logsV2": true,
      "patchId": "42e670f6-973f-49c3-a558-6f93b1d9c64e",
      "reason": "deploy",
      "runtime": "V2",
      "serviceManifest": {
        "build": {
          "buildCommand": null,
          "buildEnvironment": "V3",
          "builder": "RAILPACK",
          "dockerfilePath": null,
          "nixpacksConfigPath": null,
          "nixpacksPlan": null,
          "watchPatterns": []
        },
        "deploy": {
          "cronSchedule": null,
          "drainingSeconds": null,
          "healthcheckPath": null,
          "healthcheckTimeout": null,
          "ipv6EgressEnabled": false,
          "limitOverride": null,
          "multiRegionConfig": {
            "sin": {
              "numReplicas": 1
            }
          },
          "numReplicas": 1,
          "overlapSeconds": null,
          "preDeployCommand": null,
          "region": null,
          "registryCredentials": null,
          "requiredMountPath": null,
          "restartPolicyMaxRetries": 10,
          "restartPolicyType": "ON_FAILURE",
          "runtime": "V2",
          "sleepApplication": false,
          "startCommand": null,
          "useLegacyStacker": false
        }
      },
      "volumeMounts": []
    }
  },
  {
    "id": "14259a91-42fe-4a99-83d5-1ed99e68b40a",
    "status": "REMOVED",
    "createdAt": "2026-08-21T13:00:25.677Z",
    "meta": {
      "buildOnly": false,
      "configFile": "/railway.toml",
      "fileServiceManifest": {
        "build": {
          "builder": "DOCKERFILE",
          "dockerfilePath": "Dockerfile"
        },
        "deploy": {
          "healthcheckPath": "/health/ready",
          "healthcheckTimeout": 20,
          "restartPolicyMaxRetries": 5,
          "restartPolicyType": "ON_FAILURE"
        }
      },
      "logsV2": true,
      "nixpacksProviders": [],
      "propertyFileMapping": {
        "build.builder": "$.build.builder",
        "build.dockerfilePath": "$.build.dockerfilePath",
        "deploy.healthcheckPath": "$.deploy.healthcheckPath",
        "deploy.healthcheckTimeout": "$.deploy.healthcheckTimeout",
        "deploy.restartPolicyMaxRetries": "$.deploy.restartPolicyMaxRetries",
        "deploy.restartPolicyType": "$.deploy.restartPolicyType"
      },
      "reason": "deploy",
      "rootDirectory": null,
      "runtime": "V2",
      "serviceManifest": {
        "build": {
          "buildCommand": null,
          "buildEnvironment": "V3",
          "builder": "DOCKERFILE",
          "dockerfilePath": "Dockerfile",
          "nixpacksConfigPath": null,
          "nixpacksPlan": null,
          "watchPatterns": []
        },
        "deploy": {
          "cronSchedule": null,
          "drainingSeconds": null,
          "healthcheckPath": "/health/ready",
          "healthcheckTimeout": 20,
          "ipv6EgressEnabled": false,
          "limitOverride": null,
          "multiRegionConfig": {
            "sin": {
              "numReplicas": 1
            }
          },
          "numReplicas": 1,
          "overlapSeconds": null,
          "preDeployCommand": null,
          "region": null,
          "registryCredentials": null,
          "requiredMountPath": null,
          "restartPolicyMaxRetries": 5,
          "restartPolicyType": "ON_FAILURE",
          "runtime": "V2",
          "sleepApplication": false,
          "startCommand": null,
          "useLegacyStacker": false
        }
      },
      "volumeMounts": []
    }
  },
  {
    "id": "76a337f3-83c1-4e9b-bd9f-9cae410f733d",
    "status": "REMOVED",
    "createdAt": "2026-08-21T12:33:01.927Z",
    "meta": {
      "image": "ghcr.io/verigence/verigence-security@sha256:d929f2763d42b13631f3ebbd6f3dbe288eab9023c9d4fc754e683b1d4f554ad1",
      "imageDigest": "sha256:d929f2763d42b13631f3ebbd6f3dbe288eab9023c9d4fc754e683b1d4f554ad1",
      "logsV2": true,
      "patchId": "a7080e2c-5be6-476b-b61e-bdfdd16095cc",
      "reason": "deploy",
      "runtime": "V2",
      "serviceManifest": {
        "build": {
          "buildCommand": null,
          "buildEnvironment": "V3",
          "builder": "RAILPACK",
          "dockerfilePath": null,
          "nixpacksConfigPath": null,
          "nixpacksPlan": null,
          "watchPatterns": []
        },
        "deploy": {
          "cronSchedule": null,
          "drainingSeconds": null,
          "healthcheckPath": null,
          "healthcheckTimeout": null,
          "ipv6EgressEnabled": false,
          "limitOverride": null,
          "multiRegionConfig": {
            "sin": {
              "numReplicas": 1
            }
          },
          "numReplicas": 1,
          "overlapSeconds": null,
          "preDeployCommand": null,
          "region": null,
          "registryCredentials": null,
          "requiredMountPath": null,
          "restartPolicyMaxRetries": 10,
          "restartPolicyType": "ON_FAILURE",
          "runtime": "V2",
          "sleepApplication": false,
          "startCommand": null,
          "useLegacyStacker": false
        }
      },
      "volumeMounts": []
    }
  },
  {
    "id": "48e7b3c4-70a5-427c-9db5-d791faff5106",
    "status": "REMOVED",
    "createdAt": "2026-08-21T12:32:13.841Z",
    "meta": {
      "image": "ghcr.io/verigence/verigence-security@sha256:2c5a96b86994ef7c8384e7859e3121da53384dc840ccd5e04684d878a73a1402",
      "imageDigest": "sha256:2c5a96b86994ef7c8384e7859e3121da53384dc840ccd5e04684d878a73a1402",
      "logsV2": true,
      "patchId": "1a31b72b-7c8a-4c14-a073-6a4eb9578654",
      "reason": "deploy",
      "runtime": "V2",
      "serviceManifest": {
        "build": {
          "buildCommand": null,
          "buildEnvironment": "V3",
          "builder": "RAILPACK",
          "dockerfilePath": null,
          "nixpacksConfigPath": null,
          "nixpacksPlan": null,
          "watchPatterns": []
        },
        "deploy": {
          "cronSchedule": null,
          "drainingSeconds": null,
          "healthcheckPath": null,
          "healthcheckTimeout": null,
          "ipv6EgressEnabled": false,
          "limitOverride": null,
          "multiRegionConfig": {
            "sin": {
              "numReplicas": 1
            }
          },
          "numReplicas": 1,
          "overlapSeconds": null,
          "preDeployCommand": null,
          "region": null,
          "registryCredentials": null,
          "requiredMountPath": null,
          "restartPolicyMaxRetries": 10,
          "restartPolicyType": "ON_FAILURE",
          "runtime": "V2",
          "sleepApplication": false,
          "startCommand": null,
          "useLegacyStacker": false
        }
      },
      "volumeMounts": []
    }
  },
  {
    "id": "99f84f8e-641a-420a-8264-e69e2834fd74",
    "status": "REMOVED",
    "createdAt": "2026-08-21T12:31:51.622Z",
    "meta": {
      "buildOnly": false,
      "configFile": "/railway.toml",
      "fileServiceManifest": {
        "build": {
          "builder": "DOCKERFILE",
          "dockerfilePath": "Dockerfile"
        },
        "deploy": {
          "healthcheckPath": "/health/ready",
          "healthcheckTimeout": 20,
          "restartPolicyMaxRetries": 5,
          "restartPolicyType": "ON_FAILURE"
        }
      },
      "logsV2": true,
      "nixpacksProviders": [],
      "propertyFileMapping": {
        "build.builder": "$.build.builder",
        "build.dockerfilePath": "$.build.dockerfilePath",
        "deploy.healthcheckPath": "$.deploy.healthcheckPath",
        "deploy.healthcheckTimeout": "$.deploy.healthcheckTimeout",
        "deploy.restartPolicyMaxRetries": "$.deploy.restartPolicyMaxRetries",
        "deploy.restartPolicyType": "$.deploy.restartPolicyType"
      },
      "reason": "deploy",
      "rootDirectory": null,
      "runtime": "V2",
      "serviceManifest": {
        "build": {
          "buildCommand": null,
          "buildEnvironment": "V3",
          "builder": "DOCKERFILE",
          "dockerfilePath": "Dockerfile",
          "nixpacksConfigPath": null,
          "nixpacksPlan": null,
          "watchPatterns": []
        },
        "deploy": {
          "cronSchedule": null,
          "drainingSeconds": null,
          "healthcheckPath": "/health/ready",
          "healthcheckTimeout": 20,
          "ipv6EgressEnabled": false,
          "limitOverride": null,
          "multiRegionConfig": {
            "sin": {
              "numReplicas": 1
            }
          },
          "numReplicas": 1,
          "overlapSeconds": null,
          "preDeployCommand": null,
          "region": null,
          "registryCredentials": null,
          "requiredMountPath": null,
          "restartPolicyMaxRetries": 5,
          "restartPolicyType": "ON_FAILURE",
          "runtime": "V2",
          "sleepApplication": false,
          "startCommand": null,
          "useLegacyStacker": false
        }
      },
      "volumeMounts": []
    }
  },
  {
    "id": "e252c9f8-8407-45c1-b4b9-924f5f55d8dc",
    "status": "REMOVED",
    "createdAt": "2026-08-21T12:04:29.436Z",
    "meta": {
      "buildOnly": false,
      "configFile": "/railway.toml",
      "fileServiceManifest": {
        "build": {
          "builder": "DOCKERFILE",
          "dockerfilePath": "Dockerfile"
        },
        "deploy": {
          "healthcheckPath": "/health/ready",
          "healthcheckTimeout": 20,
          "restartPolicyMaxRetries": 5,
          "restartPolicyType": "ON_FAILURE"
        }
      },
      "imageDigest": "sha256:b01cd8b6adf98a06f28e114b495ab5bd17a1b03ce568326cdb11e4a529fdf895",
      "logsV2": true,
      "nixpacksProviders": [],
      "propertyFileMapping": {
        "build.builder": "$.build.builder",
        "build.dockerfilePath": "$.build.dockerfilePath",
        "deploy.healthcheckPath": "$.deploy.healthcheckPath",
        "deploy.healthcheckTimeout": "$.deploy.healthcheckTimeout",
        "deploy.restartPolicyMaxRetries": "$.deploy.restartPolicyMaxRetries",
        "deploy.restartPolicyType": "$.deploy.restartPolicyType"
      },
      "reason": "deploy",
      "rootDirectory": null,
      "runtime": "V2",
      "serviceManifest": {
        "build": {
          "buildCommand": null,
          "buildEnvironment": "V3",
          "builder": "DOCKERFILE",
          "dockerfilePath": "Dockerfile",
          "nixpacksConfigPath": null,
          "nixpacksPlan": null,
          "wat
```

## Sanitized auth-stage logs
```text
{"timestamp":"2026-08-21T13:45:54.661237617Z","message":"Human credential authentication denied; stage=clerk_password_verification_rejected","level":"error"}
{"timestamp":"2026-08-21T13:45:54.661244164Z","message":"INFO:     100.64.0.2:18930 - \"POST /security/v1/auth/login HTTP/1.1\" 401 Unauthorized","level":"info"}
```
