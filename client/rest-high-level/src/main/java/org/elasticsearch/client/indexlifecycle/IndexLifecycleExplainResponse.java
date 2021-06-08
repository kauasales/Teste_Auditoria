/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0 and the Server Side Public License, v 1; you may not use this file except
 * in compliance with, at your election, the Elastic License 2.0 or the Server
 * Side Public License, v 1.
 */

package org.elasticsearch.client.indexlifecycle;

import org.elasticsearch.common.ParseField;
import org.elasticsearch.common.Strings;
import org.elasticsearch.common.bytes.BytesReference;
import org.elasticsearch.core.TimeValue;
import org.elasticsearch.common.xcontent.ConstructingObjectParser;
import org.elasticsearch.common.xcontent.ToXContentObject;
import org.elasticsearch.common.xcontent.XContentBuilder;
import org.elasticsearch.common.xcontent.XContentType;
import org.elasticsearch.common.xcontent.json.JsonXContent;

import java.io.IOException;
import java.util.Objects;
import java.util.stream.Stream;

public class IndexLifecycleExplainResponse implements ToXContentObject {

    private static final ParseField INDEX_FIELD = new ParseField("index");
    private static final ParseField MANAGED_BY_ILM_FIELD = new ParseField("managed");
    private static final ParseField POLICY_NAME_FIELD = new ParseField("policy");
    private static final ParseField LIFECYCLE_DATE_MILLIS_FIELD = new ParseField("lifecycle_date_millis");
    private static final ParseField LIFECYCLE_DATE_FIELD = new ParseField("lifecycle_date");
    private static final ParseField PHASE_FIELD = new ParseField("phase");
    private static final ParseField ACTION_FIELD = new ParseField("action");
    private static final ParseField STEP_FIELD = new ParseField("step");
    private static final ParseField FAILED_STEP_FIELD = new ParseField("failed_step");
    private static final ParseField PHASE_TIME_MILLIS_FIELD = new ParseField("phase_time_millis");
    private static final ParseField PHASE_TIME_FIELD = new ParseField("phase_time");
    private static final ParseField ACTION_TIME_MILLIS_FIELD = new ParseField("action_time_millis");
    private static final ParseField ACTION_TIME_FIELD = new ParseField("action_time");
    private static final ParseField STEP_TIME_MILLIS_FIELD = new ParseField("step_time_millis");
    private static final ParseField STEP_TIME_FIELD = new ParseField("step_time");
    private static final ParseField STEP_INFO_FIELD = new ParseField("step_info");
    private static final ParseField PHASE_EXECUTION_INFO = new ParseField("phase_execution");
    private static final ParseField AGE_FIELD = new ParseField("age");

    public static final ConstructingObjectParser<IndexLifecycleExplainResponse, Void> PARSER = new ConstructingObjectParser<>(
        "index_lifecycle_explain_response", true,
        a -> new IndexLifecycleExplainResponse(
            (String) a[0],
            (boolean) a[1],
            (String) a[2],
            (Long) a[3],
            (String) a[4],
            (String) a[5],
            (String) a[6],
            (String) a[7],
            (Long) a[8],
            (Long) a[9],
            (Long) a[10],
            (BytesReference) a[11],
            (PhaseExecutionInfo) a[12]));
    static {
        PARSER.declareString(ConstructingObjectParser.constructorArg(), INDEX_FIELD);
        PARSER.declareBoolean(ConstructingObjectParser.constructorArg(), MANAGED_BY_ILM_FIELD);
        PARSER.declareString(ConstructingObjectParser.optionalConstructorArg(), POLICY_NAME_FIELD);
        PARSER.declareLong(ConstructingObjectParser.optionalConstructorArg(), LIFECYCLE_DATE_MILLIS_FIELD);
        PARSER.declareString(ConstructingObjectParser.optionalConstructorArg(), PHASE_FIELD);
        PARSER.declareString(ConstructingObjectParser.optionalConstructorArg(), ACTION_FIELD);
        PARSER.declareString(ConstructingObjectParser.optionalConstructorArg(), STEP_FIELD);
        PARSER.declareString(ConstructingObjectParser.optionalConstructorArg(), FAILED_STEP_FIELD);
        PARSER.declareLong(ConstructingObjectParser.optionalConstructorArg(), PHASE_TIME_MILLIS_FIELD);
        PARSER.declareLong(ConstructingObjectParser.optionalConstructorArg(), ACTION_TIME_MILLIS_FIELD);
        PARSER.declareLong(ConstructingObjectParser.optionalConstructorArg(), STEP_TIME_MILLIS_FIELD);
        PARSER.declareObject(ConstructingObjectParser.optionalConstructorArg(), (p, c) -> {
            XContentBuilder builder = JsonXContent.contentBuilder();
            builder.copyCurrentStructure(p);
            return BytesReference.bytes(builder);
        }, STEP_INFO_FIELD);
        PARSER.declareObject(ConstructingObjectParser.optionalConstructorArg(), (p, c) -> PhaseExecutionInfo.parse(p, ""),
            PHASE_EXECUTION_INFO);
    }

    private final String index;
    private final String policyName;
    private final String phase;
    private final String action;
    private final String step;
    private final String failedStep;
    private final Long lifecycleDate;
    private final Long phaseTime;
    private final Long actionTime;
    private final Long stepTime;
    private final boolean managedByILM;
    private final BytesReference stepInfo;
    private final PhaseExecutionInfo phaseExecutionInfo;

    public static IndexLifecycleExplainResponse newManagedIndexResponse(String index, String policyName, Long lifecycleDate,
                                                                        String phase, String action, String step, String failedStep,
                                                                        Long phaseTime, Long actionTime, Long stepTime,
                                                                        BytesReference stepInfo, PhaseExecutionInfo phaseExecutionInfo) {
        return new IndexLifecycleExplainResponse(index, true, policyName, lifecycleDate, phase, action, step, failedStep, phaseTime,
            actionTime, stepTime, stepInfo, phaseExecutionInfo);
    }

    public static IndexLifecycleExplainResponse newUnmanagedIndexResponse(String index) {
        return new IndexLifecycleExplainResponse(index, false, null, null, null, null, null, null, null, null, null, null, null);
    }

    private IndexLifecycleExplainResponse(String index, boolean managedByILM, String policyName, Long lifecycleDate,
                                          String phase, String action, String step, String failedStep, Long phaseTime, Long actionTime,
                                          Long stepTime, BytesReference stepInfo, PhaseExecutionInfo phaseExecutionInfo) {
        if (managedByILM) {
            if (policyName == null) {
                throw new IllegalArgumentException("[" + POLICY_NAME_FIELD.getPreferredName() + "] cannot be null for managed index");
            }
            // check to make sure that step details are either all null or all set.
            long numNull = Stream.of(phase, action, step).filter(Objects::isNull).count();
            if (numNull > 0 && numNull < 3) {
                throw new IllegalArgumentException("managed index response must have complete step details [" +
                    PHASE_FIELD.getPreferredName() + "=" + phase + ", " +
                    ACTION_FIELD.getPreferredName() + "=" + action + ", " +
                    STEP_FIELD.getPreferredName() + "=" + step + "]");
            }
        } else {
            if (policyName != null || lifecycleDate != null || phase != null || action != null || step != null || failedStep != null
                || phaseTime != null || actionTime != null || stepTime != null || stepInfo != null || phaseExecutionInfo != null) {
                throw new IllegalArgumentException(
                    "Unmanaged index response must only contain fields: [" + MANAGED_BY_ILM_FIELD + ", " + INDEX_FIELD + "]");
            }
        }
        this.index = index;
        this.policyName = policyName;
        this.managedByILM = managedByILM;
        this.lifecycleDate = lifecycleDate;
        this.phase = phase;
        this.action = action;
        this.step = step;
        this.phaseTime = phaseTime;
        this.actionTime = actionTime;
        this.stepTime = stepTime;
        this.failedStep = failedStep;
        this.stepInfo = stepInfo;
        this.phaseExecutionInfo = phaseExecutionInfo;
    }

    public String getIndex() {
        return index;
    }

    public boolean managedByILM() {
        return managedByILM;
    }

    public String getPolicyName() {
        return policyName;
    }

    public long getLifecycleDate() {
        return lifecycleDate;
    }

    public String getPhase() {
        return phase;
    }

    public long getPhaseTime() {
        return phaseTime;
    }

    public String getAction() {
        return action;
    }

    public long getActionTime() {
        return actionTime;
    }

    public String getStep() {
        return step;
    }

    public long getStepTime() {
        return stepTime;
    }

    public String getFailedStep() {
        return failedStep;
    }

    public BytesReference getStepInfo() {
        return stepInfo;
    }

    public PhaseExecutionInfo getPhaseExecutionInfo() {
        return phaseExecutionInfo;
    }

    public TimeValue getAge() {
        if (lifecycleDate == null) {
            return TimeValue.MINUS_ONE;
        } else {
            return TimeValue.timeValueMillis(System.currentTimeMillis() - lifecycleDate);
        }
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        builder.startObject();
        builder.field(INDEX_FIELD.getPreferredName(), index);
        builder.field(MANAGED_BY_ILM_FIELD.getPreferredName(), managedByILM);
        if (managedByILM) {
            builder.field(POLICY_NAME_FIELD.getPreferredName(), policyName);
            if (lifecycleDate != null) {
                builder.timeField(LIFECYCLE_DATE_MILLIS_FIELD.getPreferredName(), LIFECYCLE_DATE_FIELD.getPreferredName(), lifecycleDate);
                builder.field(AGE_FIELD.getPreferredName(), getAge().toHumanReadableString(2));
            }
            if (phase != null) {
                builder.field(PHASE_FIELD.getPreferredName(), phase);
            }
            if (phaseTime != null) {
                builder.timeField(PHASE_TIME_MILLIS_FIELD.getPreferredName(), PHASE_TIME_FIELD.getPreferredName(), phaseTime);
            }
            if (action != null) {
                builder.field(ACTION_FIELD.getPreferredName(), action);
            }
            if (actionTime != null) {
                builder.timeField(ACTION_TIME_MILLIS_FIELD.getPreferredName(), ACTION_TIME_FIELD.getPreferredName(), actionTime);
            }
            if (step != null) {
                builder.field(STEP_FIELD.getPreferredName(), step);
            }
            if (stepTime != null) {
                builder.timeField(STEP_TIME_MILLIS_FIELD.getPreferredName(), STEP_TIME_FIELD.getPreferredName(), stepTime);
            }
            if (Strings.hasLength(failedStep)) {
                builder.field(FAILED_STEP_FIELD.getPreferredName(), failedStep);
            }
            if (stepInfo != null && stepInfo.length() > 0) {
                builder.rawField(STEP_INFO_FIELD.getPreferredName(), stepInfo.streamInput(), XContentType.JSON);
            }
            if (phaseExecutionInfo != null) {
                builder.field(PHASE_EXECUTION_INFO.getPreferredName(), phaseExecutionInfo);
            }
        }
        builder.endObject();
        return builder;
    }

    @Override
    public int hashCode() {
        return Objects.hash(index, managedByILM, policyName, lifecycleDate, phase, action, step, failedStep, phaseTime, actionTime,
            stepTime, stepInfo, phaseExecutionInfo);
    }

    @Override
    public boolean equals(Object obj) {
        if (obj == null) {
            return false;
        }
        if (obj.getClass() != getClass()) {
            return false;
        }
        IndexLifecycleExplainResponse other = (IndexLifecycleExplainResponse) obj;
        return Objects.equals(index, other.index) &&
            Objects.equals(managedByILM, other.managedByILM) &&
            Objects.equals(policyName, other.policyName) &&
            Objects.equals(lifecycleDate, other.lifecycleDate) &&
            Objects.equals(phase, other.phase) &&
            Objects.equals(action, other.action) &&
            Objects.equals(step, other.step) &&
            Objects.equals(failedStep, other.failedStep) &&
            Objects.equals(phaseTime, other.phaseTime) &&
            Objects.equals(actionTime, other.actionTime) &&
            Objects.equals(stepTime, other.stepTime) &&
            Objects.equals(stepInfo, other.stepInfo) &&
            Objects.equals(phaseExecutionInfo, other.phaseExecutionInfo);
    }

    @Override
    public String toString() {
        return Strings.toString(this, true, true);
    }

}

