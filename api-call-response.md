

## response

### generateContent
```
{
  "candidates": [
    {
      "avgLogprobs": -0.10110127925872803,
      "content": {
        "parts": [
          {
            "text": "Want to play ArcheAge later?\n"
          }
        ],
        "role": "model"
      },
      "finishReason": "STOP",
      "safetyRatings": [
        {
          "category": "HARM_CATEGORY_HATE_SPEECH",
          "probability": "NEGLIGIBLE",
          "probabilityScore": 6.8904126e-05,
          "severity": "HARM_SEVERITY_NEGLIGIBLE"
        },
        {
          "category": "HARM_CATEGORY_DANGEROUS_CONTENT",
          "probability": "NEGLIGIBLE",
          "probabilityScore": 1.3628356e-05,
          "severity": "HARM_SEVERITY_NEGLIGIBLE"
        },
        {
          "category": "HARM_CATEGORY_HARASSMENT",
          "probability": "NEGLIGIBLE",
          "probabilityScore": 5.735116e-05,
          "severity": "HARM_SEVERITY_NEGLIGIBLE"
        },
        {
          "category": "HARM_CATEGORY_SEXUALLY_EXPLICIT",
          "probability": "NEGLIGIBLE",
          "probabilityScore": 0.0003534873,
          "severity": "HARM_SEVERITY_NEGLIGIBLE",
          "severityScore": 0.022611141
        }
      ]
    }
  ],
  "createTime": "2025-04-18T05:14:44.297871Z",
  "modelVersion": "gemini-2.0-flash-lite-001",
  "responseId": "xN8BaI-XEpqBm9IP_Jay0Ag",
  "usageMetadata": {
    "candidatesTokenCount": 8,
    "candidatesTokensDetails": [
      {
        "modality": "TEXT",
        "tokenCount": 8
      }
    ],
    "promptTokenCount": 38,
    "promptTokensDetails": [
      {
        "modality": "TEXT",
        "tokenCount": 38
      }
    ],
    "totalTokenCount": 46,
    "trafficType": "ON_DEMAND"
  }
}
```


### streamGenerateContent
```
[
    {
        "candidates": [
            {
                "content": {
                    "parts": [
                        {
                            "text": "Hello"
                        }
                    ],
                    "role": "model"
                }
            }
        ],
        "createTime": "2025-04-18T04:01:43.287321Z",
        "modelVersion": "gemini-2.0-flash-lite-001",
        "responseId": "p84BaNnEEYyem9IPqfCm6QU",
        "usageMetadata": {
            "trafficType": "ON_DEMAND"
        }
    },
    {
        "candidates": [
            {
                "content": {
                    "parts": [
                        {
                            "text": "?\n"
                        }
                    ],
                    "role": "model"
                },
                "finishReason": "STOP",
                "safetyRatings": [
                    {
                        "category": "HARM_CATEGORY_HATE_SPEECH",
                        "probability": "NEGLIGIBLE",
                        "probabilityScore": 2.5835377e-07,
                        "severity": "HARM_SEVERITY_NEGLIGIBLE"
                    },
                    {
                        "category": "HARM_CATEGORY_DANGEROUS_CONTENT",
                        "probability": "NEGLIGIBLE",
                        "probabilityScore": 2.5147664e-08,
                        "severity": "HARM_SEVERITY_NEGLIGIBLE",
                        "severityScore": 0.06104049
                    },
                    {
                        "category": "HARM_CATEGORY_HARASSMENT",
                        "probability": "NEGLIGIBLE",
                        "probabilityScore": 1.1431367e-05,
                        "severity": "HARM_SEVERITY_NEGLIGIBLE"
                    },
                    {
                        "category": "HARM_CATEGORY_SEXUALLY_EXPLICIT",
                        "probability": "NEGLIGIBLE",
                        "probabilityScore": 9.814705e-08,
                        "severity": "HARM_SEVERITY_NEGLIGIBLE",
                        "severityScore": 0.005992353
                    }
                ]
            }
        ],
        "createTime": "2025-04-18T04:01:43.287321Z",
        "modelVersion": "gemini-2.0-flash-lite-001",
        "responseId": "p84BaNnEEYyem9IPqfCm6QU",
        "usageMetadata": {
            "candidatesTokenCount": 3,
            "candidatesTokensDetails": [
                {
                    "modality": "TEXT",
                    "tokenCount": 3
                }
            ],
            "promptTokenCount": 31,
            "promptTokensDetails": [
                {
                    "modality": "TEXT",
                    "tokenCount": 31
                }
            ],
            "totalTokenCount": 34,
            "trafficType": "ON_DEMAND"
        }
    }
]
```