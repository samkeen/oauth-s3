# Docs in progress

## Rough AWS Notes

### Create your Bucket

Defaults to only visible via the credentials of who created it

### Setting Up Bucket Authentication

Create a IAM User

Attach a User Policy

```javascript
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:Get*",
        "s3:List*"
      ],
      "Resource": [
        "arn:aws:s3:::BUCKET-NAME",
        "arn:aws:s3:::BUCKET-NAME/*"
      ]
    }
  ]
}
```