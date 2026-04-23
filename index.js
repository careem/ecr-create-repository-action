const core = require('@actions/core');
const github = require('@actions/github');
const {
  ECR,
  DescribeRepositoriesCommand,
  CreateRepositoryCommand,
  SetRepositoryPolicyCommand
} = require('@aws-sdk/client-ecr');

const ecr = new ECR();

const executeGitHubAction = async () => {
  const ecrRepoName = core.getInput('ecr-name') || github.context.payload.repository.name;
  const pullAccountIds = core.getInput('pull-account-ids') || '';
  const allowOrgPull = core.getInput('allow-org-pull') === 'true';
  const orgId = core.getInput('org-id') || '';
  let wantedEcrRepo;

  if (allowOrgPull && !orgId) {
    core.setFailed("'org-id' is required when 'allow-org-pull' is true.");
    return;
  }

  try {
    core.info(`Checking ECR repo '${ecrRepoName}'.`);
    wantedEcrRepo = await ecr.send(new DescribeRepositoriesCommand({ repositoryNames: [ecrRepoName] }))
    wantedEcrRepo = wantedEcrRepo.repositories[0];

    core.info(`ECR repo '${ecrRepoName}' already exists.`);
  } catch (error) {
    if (error.name !== 'RepositoryNotFoundException') {
      throw error;
    }

    core.info(`ECR repo '${ecrRepoName}' does not exist.`);
    const tags = [ { "Key": "c-service", "Value": ecrRepoName }];
    wantedEcrRepo = await createNewEcrRepo(ecrRepoName, tags);
    wantedEcrRepo = wantedEcrRepo.repository;
  }

  await updateRepositoryPolicyIfRequired(ecrRepoName, pullAccountIds, allowOrgPull, orgId);

  core.setOutput('ecr-name', wantedEcrRepo.repositoryName);
  core.setOutput('ecr-arn', wantedEcrRepo.repositoryArn);
  core.setOutput('ecr-uri', wantedEcrRepo.repositoryUri);
};

const createNewEcrRepo = async (repoName, tags) => {
  core.info(`Create new ECR repo '${repoName}'.`);

  const params = {
    "repositoryName": repoName,
    "imageScanningConfiguration": {
      "scanOnPush": false
    },
    "tags": tags
  };
  return await ecr.send(new CreateRepositoryCommand(params));
};

const buildOrgPolicy = (orgId) => ({
  "Version": "2008-10-17",
  "Statement": [
    {
      "Sid": "AllowOrgWidePull",
      "Effect": "Allow",
      "Principal": "*",
      "Action": [
        "ecr:BatchCheckLayerAvailability",
        "ecr:BatchGetImage",
        "ecr:GetDownloadUrlForLayer"
      ],
      "Condition": {
        "StringEquals": {
          "aws:PrincipalOrgID": orgId
        }
      }
    }
  ]
});

const buildAccountPolicy = (pullAccountIds) => {
  const principals = pullAccountIds.split(',').map((id) => `arn:aws:iam::${id.trim()}:root`);
  principals.sort();

  const lambdaSourceArns = pullAccountIds.split(',').map((id) => `arn:aws:lambda:eu-west-1:${id.trim()}:function:*`);
  lambdaSourceArns.sort();

  return {
    policy: {
      "Version": "2008-10-17",
      "Statement": [
        {
          "Sid": "AllowCrossAccountPull",
          "Effect": "Allow",
          "Principal": { "AWS": principals },
          "Action": [
            "ecr:BatchCheckLayerAvailability",
            "ecr:BatchGetImage",
            "ecr:GetDownloadUrlForLayer"
          ]
        },
        {
          "Sid": "LambdaECRImageRetrievalPolicy",
          "Effect": "Allow",
          "Principal": { "Service": "lambda.amazonaws.com" },
          "Action": [
            "ecr:BatchGetImage",
            "ecr:DeleteRepositoryPolicy",
            "ecr:GetDownloadUrlForLayer",
            "ecr:GetRepositoryPolicy",
            "ecr:SetRepositoryPolicy"
          ],
          "Condition": {
            "StringLike": { "aws:sourceArn": lambdaSourceArns }
          }
        }
      ]
    },
    principals
  };
};

const updateRepositoryPolicyIfRequired = async (repoName, pullAccountIds, allowOrgPull, orgId) => {
  let policy;
  let shouldApply;

  if (allowOrgPull) {
    policy = buildOrgPolicy(orgId);
    shouldApply = true;
  } else {
    const { policy: accountPolicy, principals } = buildAccountPolicy(pullAccountIds);
    policy = accountPolicy;
    shouldApply = principals.length > 0;
  }

  if (!shouldApply) return;

  const newPolicyText = JSON.stringify(policy);
  let updateRepositoryPolicy = false;

  try {
    const r = await ecr.getRepositoryPolicy({ repositoryName: repoName });
    if (JSON.stringify(JSON.parse(r.policyText)) !== newPolicyText) {
      updateRepositoryPolicy = true;
    }
  } catch (error) {
    if (error.name !== 'RepositoryPolicyNotFoundException') throw error;
    updateRepositoryPolicy = true;
  }

  if (updateRepositoryPolicy) {
    core.info(`Set policy permission to ECR repo '${repoName}':`);
    core.info(newPolicyText);
    await ecr.send(new SetRepositoryPolicyCommand({ repositoryName: repoName, policyText: newPolicyText }));
  }
}

module.exports = {
  executeGitHubAction,
  buildOrgPolicy,
  buildAccountPolicy,
};

/* istanbul ignore if */
if (process.env.NODE_ENV !== 'test') {
  executeGitHubAction();
}
