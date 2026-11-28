package org.jenkinsci.plugins.pipeline.modeldefinition.actions;

import hudson.model.Node;
import hudson.slaves.DumbSlave;
import org.jenkinsci.plugins.workflow.cps.CpsFlowDefinition;
import org.jenkinsci.plugins.workflow.job.WorkflowJob;
import org.jenkinsci.plugins.workflow.job.WorkflowRun;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.JenkinsRule;

public class ObaafInstallControllerTest {
    @Rule public JenkinsRule j = new JenkinsRule();

    @Test public void twoIndependentInstalls() throws Exception {
        DumbSlave agent = j.createOnlineSlave();
        agent.setLabelString("exclusive-fixture");
        agent.setMode(Node.Mode.EXCLUSIVE);
        j.jenkins.setNumExecutors(0);
        WorkflowJob job = j.jenkins.createProject(WorkflowJob.class, "two-installs");
        String pipeline = """
            pipeline {
                agent { label 'exclusive-fixture' }
                options { disableConcurrentBuilds(); disableRestartFromStage() }
                stages {
                    stage('Before approval') { steps { sh 'bash "$PROBE_ROOT/verify-stage.sh" before' } }
                    stage('Full verification') { steps { sh 'bash "$PROBE_ROOT/verify-stage.sh" after' } }
                }
            }
            """;
        job.setDefinition(new CpsFlowDefinition(pipeline, true));
        WorkflowRun run = j.buildAndAssertSuccess(job);
        j.assertLogContains("OBAAF pre-approval checks passed with upload withheld", run);
        j.assertLogContains("OBAAF distinct second installation withheld upload without approval and allowed the named fixture approval", run);
        System.out.println("OBAAF controller verified both installations and all three fixture decisions.");
    }
}
