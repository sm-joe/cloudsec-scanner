resource "aws_s3_bucket" "insecure" {
  bucket        = "cloudsec-scanner-insecure-fixture"
  force_destroy = true
}

resource "aws_s3_bucket_acl" "public" {
  bucket = aws_s3_bucket.insecure.id
  acl    = "public-read"
}

resource "aws_ebs_volume" "insecure" {
  availability_zone = "us-east-1a"
  size              = 10
  encrypted         = false
}