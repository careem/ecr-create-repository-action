'use strict';

const test = require('ava');
const sinon = require('sinon');
const proxyquire = require('proxyquire').noCallThru();

const { buildOrgPolicy, buildAccountPolicy } = require('../index');

// ─── Pure function tests (no mocking needed) ──────────────────────────────────

test('buildOrgPolicy returns AllowOrgWidePull and LambdaECRImageRetrievalPolicy statements', (t) => {
  const policy = buildOrgPolicy('o-0xh5ns90gb');

  t.is(policy.Version, '2008-10-17');
  t.is(policy.Statement.length, 2);

  const pullStmt = policy.Statement.find((s) => s.Sid === 'AllowOrgWidePull');
  t.truthy(pullStmt);
  t.is(pullStmt.Effect, 'Allow');
  t.is(pullStmt.Principal, '*');
  t.is(pullStmt.Condition.StringEquals['aws:PrincipalOrgID'], 'o-0xh5ns90gb');
  t.deepEqual(pullStmt.Action, [
    'ecr:BatchCheckLayerAvailability',
    'ecr:BatchGetImage',
    'ecr:GetDownloadUrlForLayer',
  ]);

  const lambdaStmt = policy.Statement.find((s) => s.Sid === 'LambdaECRImageRetrievalPolicy');
  t.truthy(lambdaStmt);
  t.is(lambdaStmt.Effect, 'Allow');
  t.is(lambdaStmt.Principal.Service, 'lambda.amazonaws.com');
  t.is(lambdaStmt.Condition.StringEquals['aws:PrincipalOrgID'], 'o-0xh5ns90gb');
});

test('buildOrgPolicy uses the org-id passed in, not a hardcoded value', (t) => {
  const policy = buildOrgPolicy('o-differentorgid');
  t.is(policy.Statement[0].Condition.StringEquals['aws:PrincipalOrgID'], 'o-differentorgid');
});

test('buildAccountPolicy returns AllowCrossAccountPull and Lambda statements', (t) => {
  const { policy } = buildAccountPolicy('111111111111,222222222222');

  t.is(policy.Version, '2008-10-17');
  t.is(policy.Statement.length, 2);

  const pullStmt = policy.Statement.find((s) => s.Sid === 'AllowCrossAccountPull');
  t.truthy(pullStmt);
  t.is(pullStmt.Effect, 'Allow');
  t.deepEqual(pullStmt.Principal.AWS, [
    'arn:aws:iam::111111111111:root',
    'arn:aws:iam::222222222222:root',
  ]);

  const lambdaStmt = policy.Statement.find((s) => s.Sid === 'LambdaECRImageRetrievalPolicy');
  t.truthy(lambdaStmt);
  t.is(lambdaStmt.Principal.Service, 'lambda.amazonaws.com');
  t.deepEqual(lambdaStmt.Condition.StringLike['aws:sourceArn'], [
    'arn:aws:lambda:eu-west-1:111111111111:function:*',
    'arn:aws:lambda:eu-west-1:222222222222:function:*',
  ]);
});

test('buildAccountPolicy trims whitespace from account IDs', (t) => {
  const { policy } = buildAccountPolicy(' 111111111111 , 222222222222 ');
  const pullStmt = policy.Statement.find((s) => s.Sid === 'AllowCrossAccountPull');
  t.deepEqual(pullStmt.Principal.AWS, [
    'arn:aws:iam::111111111111:root',
    'arn:aws:iam::222222222222:root',
  ]);
});

test('buildAccountPolicy sorts principals deterministically', (t) => {
  const { policy } = buildAccountPolicy('999999999999,111111111111,555555555555');
  const pullStmt = policy.Statement.find((s) => s.Sid === 'AllowCrossAccountPull');
  t.deepEqual(pullStmt.Principal.AWS, [
    'arn:aws:iam::111111111111:root',
    'arn:aws:iam::555555555555:root',
    'arn:aws:iam::999999999999:root',
  ]);
});

test('buildAccountPolicy returns empty principals array for empty input', (t) => {
  const { principals } = buildAccountPolicy('');
  t.deepEqual(principals, ['arn:aws:iam:::root']);
});

// ─── executeGitHubAction tests (ECR + core mocked) ───────────────────────────

const makeEcrMock = (overrides = {}) => ({
  send: sinon.stub().resolves(),
  getRepositoryPolicy: sinon.stub().rejects({ name: 'RepositoryPolicyNotFoundException' }),
  ...overrides,
});

const makeCoreMock = (inputs = {}) => ({
  getInput: sinon.stub().callsFake((name) => inputs[name] ?? ''),
  setOutput: sinon.stub(),
  setFailed: sinon.stub(),
  info: sinon.stub(),
});

const makeAction = (coreMock, ecrMock) => {
  const ECRClass = class {
    constructor() {
      this.send = ecrMock.send;
      this.getRepositoryPolicy = ecrMock.getRepositoryPolicy;
    }
  };
  return proxyquire('../index', {
    '@actions/core': coreMock,
    '@aws-sdk/client-ecr': {
      ECR: ECRClass,
      DescribeRepositoriesCommand: class {},
      CreateRepositoryCommand: class {},
      SetRepositoryPolicyCommand: class { constructor(p) { this.input = p; } },
    },
  });
};

test('executeGitHubAction fails fast when allow-org-pull=true but org-id is missing', async (t) => {
  const core = makeCoreMock({ 'allow-org-pull': 'true', 'org-id': '' });
  const ecr = makeEcrMock({
    send: sinon.stub().resolves({ repositories: [{ repositoryName: 'r', repositoryArn: 'a', repositoryUri: 'u' }] }),
  });
  const { executeGitHubAction } = makeAction(core, ecr);

  await executeGitHubAction();

  t.true(core.setFailed.calledOnce);
  t.true(core.setFailed.calledWith("'org-id' is required when 'allow-org-pull' is true."));
});

test('executeGitHubAction applies org-wide policy when allow-org-pull=true', async (t) => {
  const core = makeCoreMock({ 'allow-org-pull': 'true', 'org-id': 'o-0xh5ns90gb', 'ecr-name': 'my-repo' });
  const sendStub = sinon.stub().resolves({
    repositories: [{ repositoryName: 'my-repo', repositoryArn: 'arn', repositoryUri: 'uri' }],
  });
  const ecr = makeEcrMock({ send: sendStub });
  const { executeGitHubAction } = makeAction(core, ecr);

  await executeGitHubAction();

  t.false(core.setFailed.called);

  // Last send() call is SetRepositoryPolicyCommand
  const policyCall = sendStub.args.find((args) => args[0].input?.policyText);
  t.truthy(policyCall, 'SetRepositoryPolicyCommand was called');

  const policy = JSON.parse(policyCall[0].input.policyText);
  t.is(policy.Statement.length, 2);

  const pullStmt = policy.Statement.find((s) => s.Sid === 'AllowOrgWidePull');
  t.truthy(pullStmt);
  t.is(pullStmt.Condition.StringEquals['aws:PrincipalOrgID'], 'o-0xh5ns90gb');
  t.is(pullStmt.Principal, '*');

  const lambdaStmt = policy.Statement.find((s) => s.Sid === 'LambdaECRImageRetrievalPolicy');
  t.truthy(lambdaStmt);
  t.is(lambdaStmt.Principal.Service, 'lambda.amazonaws.com');
  t.is(lambdaStmt.Condition.StringEquals['aws:PrincipalOrgID'], 'o-0xh5ns90gb');
});

test('executeGitHubAction applies per-account policy when allow-org-pull=false', async (t) => {
  const core = makeCoreMock({
    'allow-org-pull': 'false',
    'pull-account-ids': '111111111111,222222222222',
    'ecr-name': 'my-repo',
  });
  const sendStub = sinon.stub().resolves({
    repositories: [{ repositoryName: 'my-repo', repositoryArn: 'arn', repositoryUri: 'uri' }],
  });
  const ecr = makeEcrMock({ send: sendStub });
  const { executeGitHubAction } = makeAction(core, ecr);

  await executeGitHubAction();

  t.false(core.setFailed.called);

  const policyCall = sendStub.args.find((args) => args[0].input?.policyText);
  t.truthy(policyCall, 'SetRepositoryPolicyCommand was called');

  const policy = JSON.parse(policyCall[0].input.policyText);
  const pullStmt = policy.Statement.find((s) => s.Sid === 'AllowCrossAccountPull');
  t.truthy(pullStmt);
  t.deepEqual(pullStmt.Principal.AWS, [
    'arn:aws:iam::111111111111:root',
    'arn:aws:iam::222222222222:root',
  ]);
});

test('executeGitHubAction skips policy update when policy is unchanged', async (t) => {
  const orgPolicy = buildOrgPolicy('o-0xh5ns90gb');
  const core = makeCoreMock({ 'allow-org-pull': 'true', 'org-id': 'o-0xh5ns90gb', 'ecr-name': 'my-repo' });
  const sendStub = sinon.stub().resolves({
    repositories: [{ repositoryName: 'my-repo', repositoryArn: 'arn', repositoryUri: 'uri' }],
  });
  const ecr = makeEcrMock({
    send: sendStub,
    // Return the same policy that would be generated — no update needed
    getRepositoryPolicy: sinon.stub().resolves({ policyText: JSON.stringify(orgPolicy) }),
  });
  const { executeGitHubAction } = makeAction(core, ecr);

  await executeGitHubAction();

  const policyUpdateCalled = sendStub.args.some((args) => args[0].input?.policyText);
  t.false(policyUpdateCalled, 'SetRepositoryPolicyCommand should not be called when policy is unchanged');
});
