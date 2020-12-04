provider "aws" {
  region = var.awsRegion
  access_key = var.accessKey
  secret_key = var.secretAccessKey
}

resource "aws_vpc" "csye6225_demo_vpc" {
  cidr_block = var.vpcCIDR
  enable_dns_hostnames = true
  enable_dns_support = true
  enable_classiclink_dns_support = true
  tags = {
    Name = var.vpcTagName
  }
}

resource "aws_subnet" "subnet1" {
  cidr_block = var.subnet1CIDR
  vpc_id = aws_vpc.csye6225_demo_vpc.id
  availability_zone = var.subnet1AZ
  map_public_ip_on_launch = true
  tags = {
    Name = var.subnet1TagName
  }
}

resource "aws_subnet" "subnet2" {
  cidr_block = var.subnet2CIDR
  vpc_id = aws_vpc.csye6225_demo_vpc.id
  availability_zone = var.subnet2AZ
  map_public_ip_on_launch = true
  tags = {
    Name = var.subnet2TagName
  }
}
resource "aws_subnet" "subnet3" {
  cidr_block = var.subnet3CIDR
  vpc_id = aws_vpc.csye6225_demo_vpc.id
  availability_zone = var.subnet3AZ
  map_public_ip_on_launch = true
  tags = {
    Name = var.subnet3TagName
  }
}

resource "aws_internet_gateway" "gateway_for_csye6225_demo_vpc" {
  vpc_id = aws_vpc.csye6225_demo_vpc.id

  tags = {
    Name = var.internetGatewayTagName
  }
}

resource "aws_route_table" "route_table_for_3_subnets" {
  vpc_id = aws_vpc.csye6225_demo_vpc.id

  route {
    cidr_block = var.routeTableCIDR
    gateway_id = aws_internet_gateway.gateway_for_csye6225_demo_vpc.id
  }

  tags = {
    Name = var.routeTableTagName
  }
}

resource "aws_route_table_association" "association_for_subnet1" {
  subnet_id      = aws_subnet.subnet1.id
  route_table_id = aws_route_table.route_table_for_3_subnets.id
}

resource "aws_route_table_association" "association_for_subnet2" {
  subnet_id      = aws_subnet.subnet2.id
  route_table_id = aws_route_table.route_table_for_3_subnets.id
}

resource "aws_route_table_association" "association_for_subnet3" {
  subnet_id      = aws_subnet.subnet3.id
  route_table_id = aws_route_table.route_table_for_3_subnets.id
}

resource "aws_security_group" "application" {
  name = "application"
  description = "security group for ec2 instance"
  vpc_id = aws_vpc.csye6225_demo_vpc.id
  ingress {
    description = "http"
    from_port = 80
    to_port = 80
    protocol = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    description = "https"
    from_port = 443
    to_port = 443
    protocol = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    description = "ssh"
    from_port = 22
    to_port = 22
    protocol = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    description = "backend"
    from_port = 8080
    to_port = 8080
    protocol = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  egress {
    from_port = 0
    to_port = 0
    protocol = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = {
    Name = "application"
  }
}
resource "aws_security_group" "database" {
  name = "database_security_group"
  vpc_id = aws_vpc.csye6225_demo_vpc.id
  description = "Allow incoming database connections."
  ingress {
    from_port = 3306
    to_port = 3306
    protocol = "tcp"
    security_groups = [aws_security_group.application.id]
  }
  tags = {
    Name = "database"
  }
}


resource "aws_s3_bucket" "webappBucket" {
  bucket = "webapp.suheel.vallamkonda"
  acl = "private"
  force_destroy = true
  lifecycle_rule {
    id = "log"
    enabled = true
    prefix = "log/"
    tags = {
      "rule" = "log"
      "autoclean" = "true"
    }
    transition {
      days = 30
      storage_class = "STANDARD_IA"
    }
  }
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }
  cors_rule {
    allowed_headers = ["*"]
    allowed_methods = ["PUT", "POST", "GET"]
    allowed_origins = ["*"]
  }
}

resource "aws_db_subnet_group" "subnet_group_for_rds_instance" {
  name = "subnet_group_for_rds_instance"
  subnet_ids = [aws_subnet.subnet1.id, aws_subnet.subnet2.id]
  tags = {
    Name = "subnet_group_for_rds_instance"
  }
}

resource "aws_db_parameter_group" "params" {
  name = "mysql-parameters-new"
  family = "mysql8.0"
  description = "mysql parameter group"
  parameter {
    name = "performance_schema"
    value = "1"
    apply_method = "pending-reboot"
  }
}

resource "aws_db_instance" "csye6225" {
  allocated_storage = 20
  storage_type = "gp2"
  engine = "mysql"
  engine_version = "8.0"
  instance_class = "db.t3.micro"
  name = "csye6225"
  username = var.rdsUserName
  password = var.rdsPassword
  parameter_group_name = aws_db_parameter_group.params.name
  multi_az = false
  identifier = "csye6225-f20"
  db_subnet_group_name = aws_db_subnet_group.subnet_group_for_rds_instance.name
  publicly_accessible = false
  vpc_security_group_ids = [aws_security_group.database.id]
  final_snapshot_identifier = "dbinstance1-final-snapshot"
  skip_final_snapshot = "true"
  storage_encrypted = "true"
}

resource "aws_dynamodb_table" "csye6225" {
  name = "csye6225"
  hash_key = "id"
  billing_mode = "PROVISIONED"
  read_capacity = 20
  write_capacity = 20
  attribute {
    name = "id"
    type = "S"
  }
}

data "aws_iam_policy_document" "policy" {
  statement {
    actions   = [
      "s3:Get*",
      "s3:List*",
      "s3:PutObject",
      "s3:GetObject",
      "s3:DeleteObject"
    ]
    effect= "Allow"
    resources = [
      "arn:aws:s3:::${var.codedeploy_bucket}",
      "arn:aws:s3:::${var.codedeploy_bucket}/*",
      "arn:aws:s3:::${aws_s3_bucket.webappBucket.bucket}",
      "arn:aws:s3:::${aws_s3_bucket.webappBucket.bucket}/*"
    ]
  }
}


resource "aws_iam_policy" "WebAppS3" {
  name = "WebAppS3"
  description = "EC2 s3 access policy"
  policy = data.aws_iam_policy_document.policy.json
}

resource "aws_iam_role" "EC2_CSYE6225" {
  name = "EC2-CSYE6225"
  path = "/system/"
  assume_role_policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {
      "Service": "ec2.amazonaws.com"
      },
      "Effect": "Allow",
      "Sid": ""
    }
    ]
  }
  EOF
  tags = {
    role = "ec2-access"
  }
}

resource "aws_iam_role_policy_attachment" "EC2-CSYE6225_WebAppS3" {
  role = aws_iam_role.EC2_CSYE6225.name
  policy_arn = aws_iam_policy.WebAppS3.arn
}



resource "aws_iam_policy" "CodeDeploy-EC2-S3" {
  name        = "CodeDeploy-EC2-S3"
  path        = "/"
  description = "Allows EC2 instances to read data from S3 buckets"
  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": [
        "s3:Get*",
        "s3:List*",
        "s3:Put*",
        "s3:DeleteObject",
        "s3:Delete*"
	    ],
      "Effect": "Allow",
      "Resource": [
        "arn:aws:s3:::${var.codedeploy_bucket}",
        "arn:aws:s3:::${var.codedeploy_bucket}/*",
        "arn:aws:s3:::${aws_s3_bucket.webappBucket.bucket}",
        "arn:aws:s3:::${aws_s3_bucket.webappBucket.bucket}/*"
      ]
    }
  ]
}
  EOF
}

resource "aws_iam_policy" "gh-Upload-To-S3" {
  name        = "gh-Upload-To-S3"
  path        = "/"
  description = "Allows gh to upload artifacts from latest successful build to dedicated S3 bucket used by code deploy"
  policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
          "Action": [
            "s3:PutObject",
            "s3:PutObjectAcl",
            "s3:Put*",
            "s3:Get*",
            "s3:List*"
            ],
			    "Effect": "Allow",
          "Resource": [
            "arn:aws:s3:::${var.codedeploy_bucket}",
            "arn:aws:s3:::${var.codedeploy_bucket}/*"
          ]
			}
    ]
}
EOF
}

data "aws_caller_identity" "current" {}

locals {
  user_account_id = "${data.aws_caller_identity.current.account_id}"
}

resource "aws_iam_policy" "gh-Code-Deploy" {
  name        = "gh-Code-Deploy"
  path        = "/"
  description = "Allows gh to call CodeDeploy APIs to initiate application deployment on EC2 instances"
  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "codedeploy:RegisterApplicationRevision",
        "codedeploy:GetApplicationRevision"
      ],
      "Resource":
        "arn:aws:codedeploy:${var.awsRegion}:${local.user_account_id}:application:${aws_codedeploy_app.csye6225-webapp.name}"
    },
    {
      "Effect": "Allow",
      "Action": [
        "codedeploy:CreateDeployment",
        "codedeploy:GetDeployment"
      ],
      "Resource": "*"
  },
    {
      "Effect": "Allow",
      "Action": [
        "codedeploy:GetDeploymentConfig"
      ],
      "Resource": [
        "arn:aws:codedeploy:${var.awsRegion}:${local.user_account_id}:deploymentconfig:CodeDeployDefault.OneAtATime",
        "arn:aws:codedeploy:${var.awsRegion}:${local.user_account_id}:deploymentconfig:CodeDeployDefault.HalfAtATime",
        "arn:aws:codedeploy:${var.awsRegion}:${local.user_account_id}:deploymentconfig:CodeDeployDefault.AllAtOnce"
	  ]
    }
  ]
}
EOF
}



resource "aws_iam_policy" "gh-ec2-ami" {
  name = "gh-ec2-ami"
  path = "/"
  description = "This policy helps to avoid credentials"
  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "ec2:AttachVolume",
        "ec2:AuthorizeSecurityGroupIngress",
        "ec2:CopyImage",
        "ec2:CreateImage",
        "ec2:CreateKeypair",
        "ec2:CreateSecurityGroup",
        "ec2:CreateSnapshot",
        "ec2:CreateTags",
        "ec2:CreateVolume",
        "ec2:DeleteKeyPair",
        "ec2:DeleteSecurityGroup",
        "ec2:DeleteSnapshot",
        "ec2:DeleteVolume",
        "ec2:DeregisterImage",
        "ec2:DescribeImageAttribute",
        "ec2:DescribeImages",
        "ec2:DescribeInstances",
        "ec2:DescribeInstanceStatus",
        "ec2:DescribeRegions",
        "ec2:DescribeSecurityGroups",
        "ec2:DescribeSnapshots",
        "ec2:DescribeSubnets",
        "ec2:DescribeTags",
        "ec2:DescribeVolumes",
        "ec2:DetachVolume",
        "ec2:GetPasswordData",
        "ec2:ModifyImageAttribute",
        "ec2:ModifyInstanceAttribute",
        "ec2:ModifySnapshotAttribute",
        "ec2:RegisterImage",
        "ec2:RunInstances",
        "ec2:StopInstances",
        "ec2:TerminateInstances"
      ],
      "Resource": "arn:aws:s3:::${var.codedeploy_bucket}"
    }
  ]
}
EOF
}

resource "aws_iam_role" "CodeDeployServiceRole" {
  name = "CodeDeployServiceRole"
  path = "/"
  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {
        "Service": "codedeploy.amazonaws.com"
      },
      "Effect": "Allow",
      "Sid": ""
    }
  ]
}
EOF

  tags = {
    Name = "CodeDeployServiceRole"
  }
}

resource "aws_iam_role" "CodeDeployEC2ServiceRole" {
  name = "CodeDeployEC2ServiceRole"
  path = "/"
  force_detach_policies = "true"
  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {
        "Service": "ec2.amazonaws.com"
      },
      "Effect": "Allow",
      "Sid": ""
    }
  ]
}
EOF
}

resource "aws_iam_instance_profile" "deployment_profile" {
  name = "deployment_profile1"
  role = aws_iam_role.CodeDeployEC2ServiceRole.name
}

resource "aws_iam_user_policy_attachment" "policy-attach-2" {
  user       = "cicd"
  policy_arn = "${aws_iam_policy.gh-ec2-ami.arn}"
}

resource "aws_iam_user_policy_attachment" "policy-attach-1" {
  user       = "cicd"
  policy_arn = "${aws_iam_policy.gh-Code-Deploy.arn}"
}

resource "aws_iam_user_policy_attachment" "policy-attach" {
  user       = "cicd"
  policy_arn = "${aws_iam_policy.gh-Upload-To-S3.arn}"
}

resource "aws_iam_role_policy_attachment" "codedeploy_role_ec2role" {
  role       = "${aws_iam_role.CodeDeployEC2ServiceRole.name}"
  policy_arn = "${aws_iam_policy.CodeDeploy-EC2-S3.arn}"
}

resource "aws_iam_role_policy_attachment" "codedeploy_role_servicerole" {
  role       = "${aws_iam_role.CodeDeployServiceRole.name}"
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSCodeDeployRole"
}

resource "aws_iam_role_policy_attachment" "codedeploy_role2_ec2role" {
  role       = "${aws_iam_role.EC2_CSYE6225.name}"
  policy_arn = "arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy"
}

resource "aws_iam_role_policy_attachment" "codedeploy_role2_ec2role_sns" {
  role       = "${aws_iam_role.EC2_CSYE6225.name}"
  policy_arn = "arn:aws:iam::aws:policy/AmazonSNSFullAccess"
}


resource "aws_codedeploy_app" "csye6225-webapp" {
  compute_platform = "Server"
  name             = "csye6225-webapp"
}

resource "aws_codedeploy_deployment_group" "csye6225-webapp-deployment" {
  app_name              = "${aws_codedeploy_app.csye6225-webapp.name}"
  deployment_group_name = "csye6225-webapp-deployment"
  deployment_config_name = "CodeDeployDefault.AllAtOnce"
  service_role_arn      = "${aws_iam_role.CodeDeployServiceRole.arn}"
  depends_on  = [aws_iam_role.CodeDeployServiceRole]
  autoscaling_groups = ["${aws_autoscaling_group.webapp_asg.name}"]

  ec2_tag_set {
    ec2_tag_filter {
      key   = "Name"
      type  = "KEY_AND_VALUE"
      value = "Web App Instance"
    }
  }

  deployment_style {
    deployment_option = "WITHOUT_TRAFFIC_CONTROL"
    deployment_type = "IN_PLACE"
  }
}

resource "aws_route53_record" "www" {
  zone_id = var.zone_id
  name    = var.dname
  type    = "A"
  alias {
    name                   = "${aws_lb.LoadBalancer.dns_name}"
    zone_id                = "${aws_lb.LoadBalancer.zone_id}"
    evaluate_target_health = true
  }
}



resource "aws_iam_instance_profile" "s3_profile" {
  name = "s3_profile_for_webapp1"
  role = aws_iam_role.EC2_CSYE6225.name
}

resource "aws_autoscaling_group" "webapp_asg" {
  name                 = "webapp_asg"
  launch_configuration = aws_launch_configuration.asg_launch_config.name
  min_size             = 3
  max_size             = 5
  desired_capacity = 3
  default_cooldown = 60
  vpc_zone_identifier  = [aws_subnet.subnet1.id]
  target_group_arns = [aws_lb_target_group.lb_target_group.arn, aws_lb_target_group.lb_target_group_2.arn]
  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_autoscaling_policy" "web_server_scale_up_policy" {
  name                   = "web_server_scale_up_policy"
  scaling_adjustment     = 1
  adjustment_type        = "ChangeInCapacity"
  cooldown               = 60
  autoscaling_group_name = aws_autoscaling_group.webapp_asg.name
}

resource "aws_autoscaling_policy" "web_server_scale_down_policy" {
  name                   = "web_server_scale_down_policy"
  scaling_adjustment     = -1
  adjustment_type        = "ChangeInCapacity"
  cooldown               = 60
  autoscaling_group_name = aws_autoscaling_group.webapp_asg.name
}

resource "aws_cloudwatch_metric_alarm" "cpu_alarm_high" {
  alarm_name                = "cpu_alarm_high"
  comparison_operator       = "GreaterThanThreshold"
  evaluation_periods        = "2"
  metric_name               = "CPUUtilization"
  namespace                 = "AWS/EC2"
  period                    = "120"
  statistic                 = "Average"
  threshold                 = "5"
  alarm_description         = "Scale-up if CPU > 5%"
  dimensions = {
    AutoScalingGroupName = "${aws_autoscaling_group.webapp_asg.name}"
  }
  alarm_actions     = [aws_autoscaling_policy.web_server_scale_up_policy.arn]
}

resource "aws_cloudwatch_metric_alarm" "cpu_alarm_low" {
  alarm_name                = "cpu_alarm_low"
  comparison_operator       = "LessThanThreshold"
  evaluation_periods        = "2"
  metric_name               = "CPUUtilization"
  namespace                 = "AWS/EC2"
  period                    = "120"
  statistic                 = "Average"
  threshold                 = "3"
  alarm_description         = "Scale-down if CPU < 3%"
  dimensions = {
    AutoScalingGroupName = "${aws_autoscaling_group.webapp_asg.name}"
  }
  alarm_actions     = [aws_autoscaling_policy.web_server_scale_down_policy.arn]
}

resource "aws_launch_configuration" "asg_launch_config" {
  name_prefix   = "asg_launch_config"
  image_id      = var.ami
  instance_type = "t2.micro"
  key_name = var.keyPair
  associate_public_ip_address = true
  user_data = <<-EOF
                   #!/bin/bash
                 sudo touch data.txt
                 sudo echo APPLICATION_ENV=prod >> data.txt
                 sudo echo RDS_DATABASE_NAME=${aws_db_instance.csye6225.name} >> data.txt
                 sudo echo RDS_USERNAME=${aws_db_instance.csye6225.username} >> data.txt
                 sudo echo RDS_PASSWORD=${aws_db_instance.csye6225.password} >> data.txt
                 sudo echo RDS_HOSTNAME=${aws_db_instance.csye6225.address} >> data.txt
                 sudo echo S3_BUCKET_NAME=${aws_s3_bucket.webappBucket.bucket} >> data.txt
                 sudo echo TOPIC_ARN=${aws_sns_topic.user_updates.arn} >> data.txt
   EOF
  iam_instance_profile = aws_iam_instance_profile.s3_profile.name
  security_groups = [aws_security_group.application.id]
  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_lb_target_group" "lb_target_group" {
  name     = "lbtargetgp"
  port     = "3000"
  protocol = "HTTP"
  vpc_id   = aws_vpc.csye6225_demo_vpc.id
  target_type = "instance"
}

resource "aws_lb_target_group" "lb_target_group_2" {
  name     = "lbtargetgp2"
  port     = "8080"
  protocol = "HTTP"
  vpc_id   = aws_vpc.csye6225_demo_vpc.id
  target_type = "instance"
}

resource "aws_lb" "LoadBalancer" {
  name               = "LoadBalancer"
  load_balancer_type = "application"
  security_groups    = ["${aws_security_group.lb_security_grp.id}"]
  subnets            = [aws_subnet.subnet1.id, aws_subnet.subnet2.id]

  enable_deletion_protection = false

  tags = {
    Environment = "production"
  }
}

resource "aws_security_group" "lb_security_grp" {
  name        = "lb_security_grp"
  description = "Security group for load balancer"
  vpc_id      = aws_vpc.csye6225_demo_vpc.id

  ingress {
    description = "https"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "http"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "https"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    ipv6_cidr_blocks = ["::/0"]
  }

  ingress {
    description = "http"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    ipv6_cidr_blocks = ["::/0"]
  }

  ingress {
    description = "ssh"
    from_port = 22
    to_port = 22
    protocol = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "backend"
    from_port = 8080
    to_port = 8080
    protocol = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "application"
  }
}




resource "aws_lb_listener" "back_end" {
  load_balancer_arn = aws_lb.LoadBalancer.arn
  port              = "80"
  protocol          = "HTTP"
  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.lb_target_group_2.arn
  }
}

resource "aws_iam_role" "CodeDeployLambdaServiceRole" {
  name           = "CodeDeployLambdaServiceRole"
  path           = "/"
  force_detach_policies = "true"
  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {
        "Service": "lambda.amazonaws.com"
      },
      "Effect": "Allow",
      "Sid": ""
    }
  ]
}
EOF
  tags = {
    Name = "CodeDeployLambdaServiceRole"
  }
}
data "archive_file" "dummy"{
  type = "zip"
  output_path = "lambda_function_payload.zip"

  source{
    content = "hello"
    filename = "dummy.txt"
  }
}

resource "aws_lambda_function" "lambdafunctionresource" {
  filename        = "${data.archive_file.dummy.output_path}"
  function_name   = "csye6225"
  role            = "${aws_iam_role.CodeDeployLambdaServiceRole.arn}"
  handler         = var.lambda_function_handler
  runtime         = "java8"
  memory_size     = 256
  timeout         = 180
  reserved_concurrent_executions  = 5
  environment  {
    variables = {
      DOMAIN_NAME = var.dname
      table  =  "csye6225"
    }
  }
  tags = {
    Name = "Lambda Email"
  }
}

resource "aws_sns_topic" "user_updates" {
  name = "user-updates-topic"
}

resource "aws_sns_topic_subscription" "topicId" {
  topic_arn       = "${aws_sns_topic.user_updates.arn}"
  protocol        = "lambda"
  endpoint        = "${aws_lambda_function.lambdafunctionresource.arn}"
}

resource "aws_lambda_permission" "lambdapermission" {
  statement_id  = "AllowExecutionFromSNS"
  action        = "lambda:InvokeFunction"
  principal     = "sns.amazonaws.com"
  source_arn    = "${aws_sns_topic.user_updates.arn}"
  function_name = "${aws_lambda_function.lambdafunctionresource.function_name}"
}

resource "aws_iam_policy" "lambdapolicy" {
  name        = "lambdapolicy"
  policy =  <<EOF
{
          "Version" : "2012-10-17",
          "Statement": [
            {
              "Sid": "LambdaDynamoDBAccess",
              "Effect": "Allow",
              "Action": ["dynamodb:*"],
              "Resource": "arn:aws:dynamodb:${var.awsRegion}:${local.user_account_id}:table/dynamo_csye6225"
            },
            {
              "Sid": "LambdaSESAccess",
              "Effect": "Allow",
              "Action": ["ses:*"],
              "Resource": "arn:aws:ses:${var.awsRegion}:${local.user_account_id}:identity/*"
            },
            {
              "Sid": "LambdaS3Access",
              "Effect": "Allow",
              "Action": ["s3:*"],
              "Resource": "arn:aws:s3:::${var.codeDeployLambdaS3Bucket}/*"
            },
            {
              "Sid": "LambdaSNSAccess",
              "Effect": "Allow",
              "Action": ["sns:*"],
              "Resource": "${aws_sns_topic.user_updates.arn}"
            }
          ]
        }
EOF
}

resource "aws_iam_policy" "topicpolicy" {
  name        = "topicpolicy"
  description = "topicpolicy"
  policy      = <<EOF
{
          "Version" : "2012-10-17",
          "Statement": [
            {
              "Sid": "AllowEC2ToPublishToSNSTopic",
              "Effect": "Allow",
              "Action": ["sns:Publish",
              "sns:CreateTopic"],
              "Resource": "${aws_sns_topic.user_updates.arn}"
            }
          ]
        }
EOF
}

resource "aws_iam_role_policy_attachment" "lambda_policy_attach_predefinedrole" {
  role       = "${aws_iam_role.CodeDeployLambdaServiceRole.name}"
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_iam_role_policy_attachment" "lambda_policy_attach_role" {
  role       = "${aws_iam_role.CodeDeployLambdaServiceRole.name}"
  policy_arn = "arn:aws:iam::aws:policy/AWSLambdaFullAccess"
}

resource "aws_iam_role_policy_attachment" "topic_policy_attach_role" {
  role       = "${aws_iam_role.CodeDeployLambdaServiceRole.name}"
  policy_arn = "${aws_iam_policy.topicpolicy.arn}"
}

resource "aws_iam_role_policy_attachment" "bucket_policy_attach_role" {
  role       = "${aws_iam_role.CodeDeployLambdaServiceRole.name}"
  policy_arn = "${aws_iam_policy.CodeDeploy-EC2-S3.arn}"
}

resource "aws_iam_role_policy_attachment" "dynamo_policy_attach_role" {
  role       = "${aws_iam_role.CodeDeployLambdaServiceRole.name}"
  policy_arn = "arn:aws:iam::aws:policy/AmazonDynamoDBFullAccess"
}
resource "aws_iam_role_policy_attachment" "lambda_policy_attach_predefinedrole1" {
  role       = "${aws_iam_role.EC2_CSYE6225.name}"
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_iam_role_policy_attachment" "lambda_policy_attach_role1" {
  role       = "${aws_iam_role.EC2_CSYE6225.name}"
  policy_arn = "arn:aws:iam::aws:policy/AWSLambdaFullAccess"
}

resource "aws_iam_role_policy_attachment" "topic_policy_attach_role1" {
  role       = "${aws_iam_role.EC2_CSYE6225.name}"
  policy_arn = "${aws_iam_policy.topicpolicy.arn}"
}

resource "aws_iam_role_policy_attachment" "bucket_policy_attach_role1" {
  role       = "${aws_iam_role.EC2_CSYE6225.name}"
  policy_arn = "${aws_iam_policy.CodeDeploy-EC2-S3.arn}"
}

resource "aws_iam_role_policy_attachment" "dynamo_policy_attach_role1" {
  role       = "${aws_iam_role.EC2_CSYE6225.name}"
  policy_arn = "arn:aws:iam::aws:policy/AmazonDynamoDBFullAccess"
}

resource "aws_iam_role_policy_attachment" "ses_policy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonSESFullAccess"
  role = "${aws_iam_role.CodeDeployLambdaServiceRole.name}"
}