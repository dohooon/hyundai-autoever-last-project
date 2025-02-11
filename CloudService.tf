provider "aws" {
  profile = "terraform-user"
  region  = "ap-northeast-2"
}

resource "aws_security_group" "bastion-sg" {
  name_prefix = "bastion-sg-"
  vpc_id      = aws_vpc.web_service_vpc.id

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # 보안을 위해 특정 IP로 제한하는 것이 좋음
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_iam_role" "ec2_cloudwatch_role" {
  name = "EC2CloudWatchRole"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
        Effect = "Allow"
        Sid    = ""
      }
    ]
  })
}

resource "aws_iam_role_policy" "ec2_cloudwatch_policy" {
  name = "EC2CloudWatchPolicy"
  role = aws_iam_role.ec2_cloudwatch_role.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Effect   = "Allow"
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_instance_profile" "ec2_instance_profile" {
  name = "EC2InstanceProfile"
  role = aws_iam_role.ec2_cloudwatch_role.name
}

resource "aws_security_group" "database-sg" {
  name_prefix = "database-sg-"

  ingress {
    from_port   = 3306
    to_port     = 3306
    protocol    = "tcp"
    cidr_blocks = ["192.168.12.0/24"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_vpc" "web_service_vpc" {
  cidr_block           = "192.168.0.0/16"
  enable_dns_hostnames = true
  tags                 = { Name = "web_service_vpc" }
}

resource "aws_internet_gateway" "wsv-igw" {
  vpc_id = aws_vpc.web_service_vpc.id
  tags   = { Name = "wsv-igw" }
}

resource "aws_eip" "static-eip" {
  vpc = true
}

resource "aws_subnet" "nat-subnet" {
  vpc_id                  = aws_vpc.web_service_vpc.id
  cidr_block              = "192.168.1.0/24"
  availability_zone       = "ap-northeast-2a"
  map_public_ip_on_launch = true
  tags                    = { Name = "Nat-subnet" }
}

resource "aws_subnet" "bastionhost-subnet" {
  vpc_id            = aws_vpc.web_service_vpc.id
  cidr_block        = "192.168.2.0/24"
  availability_zone = "ap-northeast-2a"
  tags              = { Name = "bastion-host-subnet" }
}

resource "aws_subnet" "frontend-subnet1" {
  vpc_id            = aws_vpc.web_service_vpc.id
  cidr_block        = "192.168.10.0/24"
  availability_zone = "ap-northeast-2a"
  tags              = { Name = "frontend-subnet1" }
}

resource "aws_subnet" "backend-subnet" {
  vpc_id            = aws_vpc.web_service_vpc.id
  cidr_block        = "192.168.12.0/24"
  availability_zone = "ap-northeast-2c"
  tags              = { Name = "backend-subnet" }
}

resource "aws_nat_gateway" "wsv-natgw" {
  allocation_id = aws_eip.static-eip.id
  subnet_id     = aws_subnet.nat-subnet.id

  depends_on = [aws_eip.static-eip]
}

resource "aws_instance" "bastion-host" {
  ami                         = "ami-024ea438ab0376a47"
  instance_type               = "t2.micro"
  subnet_id                   = aws_subnet.bastionhost-subnet.id
  associate_public_ip_address = true
  key_name                    = "BastionHost"
  user_data                   = <<-EOF
              #!/bin/bash
              yum update -y
              yum install -y amazon-cloudwatch-agent

              # CloudWatch Agent 설정 파일을 EC2에 배포 (설정 파일 예시)
              cat > /opt/aws/amazon-cloudwatch-agent/bin/config.json <<EOL
              {
                "logs": {
                  "logs_collected": {
                    "files": {
                      "collect_list": [
                        {
                          "file_path": "/var/log/auth.log",
                          "log_group_name": "ec2-auth-logs",
                          "log_stream_name": "{instance_id}"
                        }
                      ]
                    }
                  }
                }
              }
              EOL

              # CloudWatch Agent 시작
              /opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl \
                -a stop \
                -c file:/opt/aws/amazon-cloudwatch-agent/bin/config.json \
                -s
              EOF

  vpc_security_group_ids = [aws_security_group.bastion-sg.id]
  tags = {
    Name = "bastion-host"
  }
}

resource "aws_instance" "frontend" {
  ami                         = "ami-024ea438ab0376a47"
  instance_type               = "t2.micro"
  subnet_id                   = aws_subnet.frontend-subnet1.id
  associate_public_ip_address = true
  key_name                    = "WebFrontEnd"
  user_data                   = <<-EOF
              #!/bin/bash
              yum update -y
              yum install -y amazon-cloudwatch-agent

              # CloudWatch Agent 설정 파일을 EC2에 배포 (설정 파일 예시)
              cat > /opt/aws/amazon-cloudwatch-agent/bin/config.json <<EOL
              {
                "logs": {
                  "logs_collected": {
                    "files": {
                      "collect_list": [
                        {
                          "file_path": "/var/log/auth.log",
                          "log_group_name": "ec2-auth-logs",
                          "log_stream_name": "{instance_id}"
                        }
                      ]
                    }
                  }
                }
              }
              EOL

              # CloudWatch Agent 시작
              /opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl \
                -a stop \
                -c file:/opt/aws/amazon-cloudwatch-agent/bin/config.json \
                -s
              EOF
  security_groups = [aws_security_group.bastion-sg.id]
  tags = {
    Name = "frontend server"
  }
}

resource "aws_instance" "backend" {
  ami           = "ami-024ea438ab0376a47"
  instance_type = "t2.micro"
  subnet_id     = aws_subnet.backend-subnet.id
  key_name      = "WebBackend"
  user_data     = <<-EOF
              #!/bin/bash
              yum update -y
              yum install -y amazon-cloudwatch-agent

              # CloudWatch Agent 설정 파일을 EC2에 배포 (설정 파일 예시)
              cat > /opt/aws/amazon-cloudwatch-agent/bin/config.json <<EOL
              {
                "logs": {
                  "logs_collected": {
                    "files": {
                      "collect_list": [
                        {
                          "file_path": "/var/log/auth.log",
                          "log_group_name": "ec2-auth-logs",
                          "log_stream_name": "{instance_id}"
                        }
                      ]
                    }
                  }
                }
              }
              EOL

              # CloudWatch Agent 시작
              /opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl \
                -a stop \
                -c file:/opt/aws/amazon-cloudwatch-agent/bin/config.json \
                -s
              EOF
  security_groups = [aws_security_group.bastion-sg.id]
  tags = {
    Name = "backend"
  }
}

resource "aws_db_instance" "web-db" {
  allocated_storage      = 20
  engine                 = "mysql"
  engine_version         = "8.0"
  instance_class         = "db.t3.micro"
  username               = "root"
  password               = "autoever6070"
  parameter_group_name   = "default.mysql8.0"
  vpc_security_group_ids = [aws_security_group.database-sg.id]
  publicly_accessible    = false
  skip_final_snapshot    = true
  tags = {
    Name = "WebServiceDB"
  }
}

# 퍼블릭 서브넷에 대한 라우팅 테이블 설정 (Bastion Host 인터넷 연결)
resource "aws_route_table" "public-route-table" {
  vpc_id = aws_vpc.web_service_vpc.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.wsv-igw.id
  }
}

resource "aws_route_table_association" "public-route-table-assoc" {
  subnet_id      = aws_subnet.bastionhost-subnet.id
  route_table_id = aws_route_table.public-route-table.id
}



# backend 서브넷에 NAT Gateway 라우팅 테이블 설정
resource "aws_route_table" "nat-route-table" {
  vpc_id = aws_vpc.web_service_vpc.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_nat_gateway.wsv-natgw.id
  }
}

resource "aws_route_table_association" "nat-route-table-assoc" {
  subnet_id      = aws_subnet.backend-subnet.id
  route_table_id = aws_route_table.nat-route-table.id
}

resource "aws_route_table_association" "front-route-table-assoc" {
    subnet_id = aws_subnet.frontend-subnet1.id
    route_table_id = aws_route_table.public-route-table.id
}

/*
  security Service 
*/
resource "aws_guardduty_detector" "guardduty_activate" {
  enable = true
}

resource "aws_cloudtrail" "cloudtrail_activate" {
  name = "web-service-cloudtrail"
  s3_bucket_name = aws_s3_bucket.cloudtrail_bucket.id
  is_multi_region_trail = true
  enable_logging = true
}

/*
  security Service bucket
*/

resource "aws_s3_bucket" "cloudtrail_bucket" {
  bucket = "cloudtrail-logs-bucket"
  force_destroy = true
}

/*
  security bucket policy
*/
resource "aws_s3_bucket_policy" "cloudtrail_bucket_policy" {
  bucket = aws_s3_bucket.cloudtrail_bucket.id
  policy = jsondecode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com"}
        Action = "s3:PutObject"
        Resource = "${aws_s3_bucket.cloudtrail_bucket.arn}/*"
      }
    ]
  })  
}




output "bastionhost-instance-ip" {
  value = aws_instance.bastion-host.public_ip
}

output "frontend-instance-ip" {
  value = aws_instance.frontend.public_ip
}