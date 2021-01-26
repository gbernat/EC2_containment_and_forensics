resource "aws_iam_role_policy" "containment_and_forensics_policy" {
  name = "containment_and_forensics_policy"
  role = aws_iam_role.containment_and_forensics_role.id
  policy = data.aws_iam_policy_document.containment_and_forensics_policy_document.json
}

resource "aws_iam_role" "containment_and_forensics_role" {
  name = "containment_and_forensics_role"
  assume_role_policy = data.aws_iam_policy_document.containment_and_forensics_assume_policy_document.json
}