# Schema Catalog

Items: 185

## 1. StrictModel

- name: StrictModel
- source_file: mirage/domain/schemas.py
- bases: ["BaseModel"]

## 2. SecurityEvent

- name: SecurityEvent
- source_file: mirage/domain/schemas.py
- bases: ["StrictModel"]

## 3. Asset

- name: Asset
- source_file: mirage/domain/schemas.py
- bases: ["StrictModel"]

## 4. Identity

- name: Identity
- source_file: mirage/domain/schemas.py
- bases: ["StrictModel"]

## 5. Relationship

- name: Relationship
- source_file: mirage/domain/schemas.py
- bases: ["StrictModel"]

## 6. TwinSnapshot

- name: TwinSnapshot
- source_file: mirage/domain/schemas.py
- bases: ["StrictModel"]

## 7. TwinUpdateResult

- name: TwinUpdateResult
- source_file: mirage/domain/schemas.py
- bases: ["StrictModel"]

## 8. TwinUpdateSummary

- name: TwinUpdateSummary
- source_file: mirage/domain/schemas.py
- bases: ["StrictModel"]

## 9. AttackStageName

- name: AttackStageName
- source_file: mirage/domain/schemas.py
- bases: ["str", "Enum"]

## 10. TimelineEvent

- name: TimelineEvent
- source_file: mirage/domain/schemas.py
- bases: ["StrictModel"]

## 11. TimelineUpdateResult

- name: TimelineUpdateResult
- source_file: mirage/domain/schemas.py
- bases: ["StrictModel"]

## 12. TimelineSnapshot

- name: TimelineSnapshot
- source_file: mirage/domain/schemas.py
- bases: ["StrictModel"]

## 13. FeatureRecord

- name: FeatureRecord
- source_file: mirage/domain/schemas.py
- bases: ["StrictModel"]

## 14. Evidence

- name: Evidence
- source_file: mirage/domain/schemas.py
- bases: ["StrictModel"]

## 15. StageScore

- name: StageScore
- source_file: mirage/domain/schemas.py
- bases: ["StrictModel"]

## 16. EntityBelief

- name: EntityBelief
- source_file: mirage/domain/schemas.py
- bases: ["StrictModel"]

## 17. IncidentBelief

- name: IncidentBelief
- source_file: mirage/domain/schemas.py
- bases: ["StrictModel"]

## 18. RuleMatch

- name: RuleMatch
- source_file: mirage/domain/schemas.py
- bases: ["StrictModel"]

## 19. CorrelationRecord

- name: CorrelationRecord
- source_file: mirage/domain/schemas.py
- bases: ["StrictModel"]

## 20. StageEstimationResult

- name: StageEstimationResult
- source_file: mirage/domain/schemas.py
- bases: ["StrictModel"]

## 21. BeliefSnapshot

- name: BeliefSnapshot
- source_file: mirage/domain/schemas.py
- bases: ["StrictModel"]

## 22. BeliefUpdateResult

- name: BeliefUpdateResult
- source_file: mirage/domain/schemas.py
- bases: ["StrictModel"]

## 23. DetectionPipelineResult

- name: DetectionPipelineResult
- source_file: mirage/domain/schemas.py
- bases: ["StrictModel"]

## 24. DetectionPipelineSummary

- name: DetectionPipelineSummary
- source_file: mirage/domain/schemas.py
- bases: ["StrictModel"]

## 25. PathType

- name: PathType
- source_file: mirage/domain/schemas.py
- bases: ["str", "Enum"]

## 26. RiskTier

- name: RiskTier
- source_file: mirage/domain/schemas.py
- bases: ["str", "Enum"]

## 27. AutomationLevel

- name: AutomationLevel
- source_file: mirage/domain/schemas.py
- bases: ["str", "Enum"]

## 28. SeedEntity

- name: SeedEntity
- source_file: mirage/domain/schemas.py
- bases: ["StrictModel"]

## 29. LocalSubgraphRequest

- name: LocalSubgraphRequest
- source_file: mirage/domain/schemas.py
- bases: ["StrictModel"]

## 30. LocalSubgraphNode

- name: LocalSubgraphNode
- source_file: mirage/domain/schemas.py
- bases: ["StrictModel"]

## 31. LocalSubgraphEdge

- name: LocalSubgraphEdge
- source_file: mirage/domain/schemas.py
- bases: ["StrictModel"]

## 32. LocalOperationalSubgraph

- name: LocalOperationalSubgraph
- source_file: mirage/domain/schemas.py
- bases: ["StrictModel"]

## 33. AttackPath

- name: AttackPath
- source_file: mirage/domain/schemas.py
- bases: ["StrictModel"]

## 34. AttackPathAnalysis

- name: AttackPathAnalysis
- source_file: mirage/domain/schemas.py
- bases: ["StrictModel"]

## 35. DeceptionPosition

- name: DeceptionPosition
- source_file: mirage/domain/schemas.py
- bases: ["StrictModel"]

## 36. CandidateDefenseAction

- name: CandidateDefenseAction
- source_file: mirage/domain/schemas.py
- bases: ["StrictModel"]

## 37. ActionConstraintResult

- name: ActionConstraintResult
- source_file: mirage/domain/schemas.py
- bases: ["StrictModel"]

## 38. ActionMask

- name: ActionMask
- source_file: mirage/domain/schemas.py
- bases: ["StrictModel"]

## 39. CandidateActionSet

- name: CandidateActionSet
- source_file: mirage/domain/schemas.py
- bases: ["StrictModel"]

## 40. AttackAnalysisResult

- name: AttackAnalysisResult
- source_file: mirage/domain/schemas.py
- bases: ["StrictModel"]

## 41. RobustDecisionInput

- name: RobustDecisionInput
- source_file: mirage/domain/schemas.py
- bases: ["StrictModel"]

## 42. SafetyVerdict

- name: SafetyVerdict
- source_file: mirage/domain/schemas.py
- bases: ["str", "Enum"]

## 43. ExecutionState

- name: ExecutionState
- source_file: mirage/domain/schemas.py
- bases: ["str", "Enum"]

## 44. ApprovalDecision

- name: ApprovalDecision
- source_file: mirage/domain/schemas.py
- bases: ["str", "Enum"]

## 45. SafetyDecision

- name: SafetyDecision
- source_file: mirage/domain/schemas.py
- bases: ["StrictModel"]

## 46. ExecutionPlan

- name: ExecutionPlan
- source_file: mirage/domain/schemas.py
- bases: ["StrictModel"]

## 47. AdapterCallResult

- name: AdapterCallResult
- source_file: mirage/domain/schemas.py
- bases: ["StrictModel"]

## 48. HealthCheckResult

- name: HealthCheckResult
- source_file: mirage/domain/schemas.py
- bases: ["StrictModel"]

## 49. StateTransitionRecord

- name: StateTransitionRecord
- source_file: mirage/domain/schemas.py
- bases: ["StrictModel"]

## 50. ExecutionRecord

- name: ExecutionRecord
- source_file: mirage/domain/schemas.py
- bases: ["StrictModel"]

## 51. ApprovalRecord

- name: ApprovalRecord
- source_file: mirage/domain/schemas.py
- bases: ["StrictModel"]

## 52. KillSwitchState

- name: KillSwitchState
- source_file: mirage/domain/schemas.py
- bases: ["StrictModel"]

## 53. AuditEvent

- name: AuditEvent
- source_file: mirage/domain/schemas.py
- bases: ["StrictModel"]

## 54. ConnectorType

- name: ConnectorType
- source_file: mirage/domain/schemas.py
- bases: ["str", "Enum"]

## 55. ConnectorHealthState

- name: ConnectorHealthState
- source_file: mirage/domain/schemas.py
- bases: ["str", "Enum"]

## 56. EntityLifecycleState

- name: EntityLifecycleState
- source_file: mirage/domain/schemas.py
- bases: ["str", "Enum"]

## 57. ShadowStatus

- name: ShadowStatus
- source_file: mirage/domain/schemas.py
- bases: ["str", "Enum"]

## 58. AnalystDecision

- name: AnalystDecision
- source_file: mirage/domain/schemas.py
- bases: ["str", "Enum"]

## 59. ConnectorConfig

- name: ConnectorConfig
- source_file: mirage/domain/schemas.py
- bases: ["StrictModel"]

## 60. RawConnectorRecord

- name: RawConnectorRecord
- source_file: mirage/domain/schemas.py
- bases: ["StrictModel"]

## 61. ConnectorCheckpoint

- name: ConnectorCheckpoint
- source_file: mirage/domain/schemas.py
- bases: ["StrictModel"]

## 62. ConnectorHealth

- name: ConnectorHealth
- source_file: mirage/domain/schemas.py
- bases: ["StrictModel"]

## 63. DiscoveryObservation

- name: DiscoveryObservation
- source_file: mirage/domain/schemas.py
- bases: ["StrictModel"]

## 64. AssetConflict

- name: AssetConflict
- source_file: mirage/domain/schemas.py
- bases: ["StrictModel"]

## 65. TwinQualityReport

- name: TwinQualityReport
- source_file: mirage/domain/schemas.py
- bases: ["StrictModel"]

## 66. DeadLetterEntry

- name: DeadLetterEntry
- source_file: mirage/domain/schemas.py
- bases: ["StrictModel"]

## 67. ConnectorPollSummary

- name: ConnectorPollSummary
- source_file: mirage/domain/schemas.py
- bases: ["StrictModel"]

## 68. CASMUpdateResult

- name: CASMUpdateResult
- source_file: mirage/domain/schemas.py
- bases: ["StrictModel"]

## 69. CASMExpirySummary

- name: CASMExpirySummary
- source_file: mirage/domain/schemas.py
- bases: ["StrictModel"]

## 70. TwinBatchUpdateSummary

- name: TwinBatchUpdateSummary
- source_file: mirage/domain/schemas.py
- bases: ["StrictModel"]

## 71. ShadowRecommendation

- name: ShadowRecommendation
- source_file: mirage/domain/schemas.py
- bases: ["StrictModel"]

## 72. AnalystFeedback

- name: AnalystFeedback
- source_file: mirage/domain/schemas.py
- bases: ["StrictModel"]

## 73. ShadowMetrics

- name: ShadowMetrics
- source_file: mirage/domain/schemas.py
- bases: ["StrictModel"]

## 74. StrictDriftModel

- name: StrictDriftModel
- source_file: mirage/drift/schema.py
- bases: ["BaseModel"]

## 75. DriftStatus

- name: DriftStatus
- source_file: mirage/drift/schema.py
- bases: ["str", "Enum"]

## 76. _StrictModel

- name: _StrictModel
- source_file: mirage/gnn/schema.py
- bases: ["BaseModel"]

## 77. SplitType

- name: SplitType
- source_file: mirage/gnn/schema.py
- bases: ["str", "Enum"]

## 78. ModelStatus

- name: ModelStatus
- source_file: mirage/gnn/schema.py
- bases: ["str", "Enum"]

## 79. GNNOperatingMode

- name: GNNOperatingMode
- source_file: mirage/gnn/schema.py
- bases: ["str", "Enum"]

## 80. StrictGovernanceModel

- name: StrictGovernanceModel
- source_file: mirage/governance/schema.py
- bases: ["BaseModel"]

## 81. ArtifactType

- name: ArtifactType
- source_file: mirage/governance/schema.py
- bases: ["str", "Enum"]

## 82. GovernanceStatus

- name: GovernanceStatus
- source_file: mirage/governance/schema.py
- bases: ["str", "Enum"]

## 83. GovernanceVerdict

- name: GovernanceVerdict
- source_file: mirage/governance/schema.py
- bases: ["str", "Enum"]

## 84. AttackStage

- name: AttackStage
- source_file: mirage/layer1_contextual_ai/attack_modeling.py
- bases: ["IntEnum"]

## 85. DeceptionActionType

- name: DeceptionActionType
- source_file: mirage/layer3_deception/deception_fabric.py
- bases: ["Enum"]

## 86. DecoyStatus

- name: DecoyStatus
- source_file: mirage/layer3_deception/deception_fabric.py
- bases: ["Enum"]

## 87. RiskLevel

- name: RiskLevel
- source_file: mirage/layer5_safe_control/safe_control.py
- bases: ["Enum"]

## 88. StrictMARLModel

- name: StrictMARLModel
- source_file: mirage/marl/schema.py
- bases: ["BaseModel"]

## 89. RangeIsolationConfig

- name: RangeIsolationConfig
- source_file: mirage/marl/schema.py
- bases: ["StrictMARLModel"]

## 90. RedActionCategory

- name: RedActionCategory
- source_file: mirage/marl/schema.py
- bases: ["str", "Enum"]

## 91. BlueActionKind

- name: BlueActionKind
- source_file: mirage/marl/schema.py
- bases: ["str", "Enum"]

## 92. RangeNode

- name: RangeNode
- source_file: mirage/marl/schema.py
- bases: ["StrictMARLModel"]

## 93. RangeEdge

- name: RangeEdge
- source_file: mirage/marl/schema.py
- bases: ["StrictMARLModel"]

## 94. RangeScenario

- name: RangeScenario
- source_file: mirage/marl/schema.py
- bases: ["StrictMARLModel"]

## 95. RedAction

- name: RedAction
- source_file: mirage/marl/schema.py
- bases: ["StrictMARLModel"]

## 96. RedActionMask

- name: RedActionMask
- source_file: mirage/marl/schema.py
- bases: ["StrictMARLModel"]

## 97. RedObservation

- name: RedObservation
- source_file: mirage/marl/schema.py
- bases: ["StrictMARLModel"]

## 98. BlueObservation

- name: BlueObservation
- source_file: mirage/marl/schema.py
- bases: ["StrictMARLModel"]

## 99. MultiAgentObservation

- name: MultiAgentObservation
- source_file: mirage/marl/schema.py
- bases: ["StrictMARLModel"]

## 100. RangeState

- name: RangeState
- source_file: mirage/marl/schema.py
- bases: ["StrictMARLModel"]

## 101. MultiAgentRewardBreakdown

- name: MultiAgentRewardBreakdown
- source_file: mirage/marl/schema.py
- bases: ["StrictMARLModel"]

## 102. MultiAgentStepResult

- name: MultiAgentStepResult
- source_file: mirage/marl/schema.py
- bases: ["StrictMARLModel"]

## 103. MARLTrajectoryStep

- name: MARLTrajectoryStep
- source_file: mirage/marl/schema.py
- bases: ["StrictMARLModel"]

## 104. MARLTrajectory

- name: MARLTrajectory
- source_file: mirage/marl/schema.py
- bases: ["StrictMARLModel"]

## 105. OpponentMetadata

- name: OpponentMetadata
- source_file: mirage/marl/schema.py
- bases: ["StrictMARLModel"]

## 106. MARLPolicyStatus

- name: MARLPolicyStatus
- source_file: mirage/marl/schema.py
- bases: ["str", "Enum"]

## 107. MARLPolicyMetadata

- name: MARLPolicyMetadata
- source_file: mirage/marl/schema.py
- bases: ["StrictMARLModel"]

## 108. RangeHealth

- name: RangeHealth
- source_file: mirage/marl/schema.py
- bases: ["StrictMARLModel"]

## 109. TrainingSummary

- name: TrainingSummary
- source_file: mirage/marl/schema.py
- bases: ["StrictMARLModel"]

## 110. ExploitabilityReport

- name: ExploitabilityReport
- source_file: mirage/marl/schema.py
- bases: ["StrictMARLModel"]

## 111. PolicyRobustnessReport

- name: PolicyRobustnessReport
- source_file: mirage/marl/schema.py
- bases: ["StrictMARLModel"]

## 112. StrictModel

- name: StrictModel
- source_file: mirage/milestone11/schema.py
- bases: ["BaseModel"]

## 113. ImplementationStatus

- name: ImplementationStatus
- source_file: mirage/milestone11/schema.py
- bases: ["str", "Enum"]

## 114. AdapterClassification

- name: AdapterClassification
- source_file: mirage/milestone11/schema.py
- bases: ["str", "Enum"]

## 115. CapabilityInventoryItem

- name: CapabilityInventoryItem
- source_file: mirage/milestone11/schema.py
- bases: ["StrictModel"]

## 116. InventoryTotals

- name: InventoryTotals
- source_file: mirage/milestone11/schema.py
- bases: ["StrictModel"]

## 117. SystemInventory

- name: SystemInventory
- source_file: mirage/milestone11/schema.py
- bases: ["StrictModel"]

## 118. SiteHealthStatus

- name: SiteHealthStatus
- source_file: mirage/milestone11/schema.py
- bases: ["str", "Enum"]

## 119. SiteRegistration

- name: SiteRegistration
- source_file: mirage/milestone11/schema.py
- bases: ["StrictModel"]

## 120. FederationTransferRequest

- name: FederationTransferRequest
- source_file: mirage/milestone11/schema.py
- bases: ["StrictModel"]

## 121. FederationDecision

- name: FederationDecision
- source_file: mirage/milestone11/schema.py
- bases: ["StrictModel"]

## 122. FederationRouteValidationRequest

- name: FederationRouteValidationRequest
- source_file: mirage/milestone11/schema.py
- bases: ["StrictModel"]

## 123. FederationPolicyValidationRequest

- name: FederationPolicyValidationRequest
- source_file: mirage/milestone11/schema.py
- bases: ["StrictModel"]

## 124. FederationStatus

- name: FederationStatus
- source_file: mirage/milestone11/schema.py
- bases: ["StrictModel"]

## 125. AssuranceSeverity

- name: AssuranceSeverity
- source_file: mirage/milestone11/schema.py
- bases: ["str", "Enum"]

## 126. AssuranceCheckResult

- name: AssuranceCheckResult
- source_file: mirage/milestone11/schema.py
- bases: ["StrictModel"]

## 127. AssuranceBundle

- name: AssuranceBundle
- source_file: mirage/milestone11/schema.py
- bases: ["StrictModel"]

## 128. ValidationJobStatus

- name: ValidationJobStatus
- source_file: mirage/milestone11/schema.py
- bases: ["str", "Enum"]

## 129. ValidationJob

- name: ValidationJob
- source_file: mirage/milestone11/schema.py
- bases: ["StrictModel"]

## 130. SoakValidationRequest

- name: SoakValidationRequest
- source_file: mirage/milestone11/schema.py
- bases: ["StrictModel"]

## 131. ChaosValidationRequest

- name: ChaosValidationRequest
- source_file: mirage/milestone11/schema.py
- bases: ["StrictModel"]

## 132. SLOReport

- name: SLOReport
- source_file: mirage/milestone11/schema.py
- bases: ["StrictModel"]

## 133. CapacityReport

- name: CapacityReport
- source_file: mirage/milestone11/schema.py
- bases: ["StrictModel"]

## 134. MaturityReport

- name: MaturityReport
- source_file: mirage/milestone11/schema.py
- bases: ["StrictModel"]

## 135. ReadinessVerdict

- name: ReadinessVerdict
- source_file: mirage/milestone11/schema.py
- bases: ["str", "Enum"]

## 136. ReadinessEvaluationRequest

- name: ReadinessEvaluationRequest
- source_file: mirage/milestone11/schema.py
- bases: ["StrictModel"]

## 137. ReadinessDecision

- name: ReadinessDecision
- source_file: mirage/milestone11/schema.py
- bases: ["StrictModel"]

## 138. StrictPilotModel

- name: StrictPilotModel
- source_file: mirage/pilot/schema.py
- bases: ["BaseModel"]

## 139. RolloutLevel

- name: RolloutLevel
- source_file: mirage/pilot/schema.py
- bases: ["str", "Enum"]

## 140. CanaryOutcome

- name: CanaryOutcome
- source_file: mirage/pilot/schema.py
- bases: ["str", "Enum"]

## 141. RuntimeMonitorStatus

- name: RuntimeMonitorStatus
- source_file: mirage/pilot/schema.py
- bases: ["str", "Enum"]

## 142. PilotFinalOutcome

- name: PilotFinalOutcome
- source_file: mirage/pilot/schema.py
- bases: ["str", "Enum"]

## 143. BackupManifest

- name: BackupManifest
- source_file: mirage/production/backup.py
- bases: ["BaseModel"]

## 144. EventMessage

- name: EventMessage
- source_file: mirage/production/events.py
- bases: ["BaseModel"]

## 145. ExecutionResult

- name: ExecutionResult
- source_file: mirage/production/execution.py
- bases: ["BaseModel"]

## 146. LeaseRecord

- name: LeaseRecord
- source_file: mirage/production/ha.py
- bases: ["BaseModel"]

## 147. MigrationResult

- name: MigrationResult
- source_file: mirage/production/migrations.py
- bases: ["BaseModel"]

## 148. EnvironmentProfile

- name: EnvironmentProfile
- source_file: mirage/production/schema.py
- bases: ["str", "Enum"]

## 149. StorageBackend

- name: StorageBackend
- source_file: mirage/production/schema.py
- bases: ["str", "Enum"]

## 150. EventTransportBackend

- name: EventTransportBackend
- source_file: mirage/production/schema.py
- bases: ["str", "Enum"]

## 151. DeploymentMode

- name: DeploymentMode
- source_file: mirage/production/schema.py
- bases: ["str", "Enum"]

## 152. DeploymentLevel

- name: DeploymentLevel
- source_file: mirage/production/schema.py
- bases: ["str", "Enum"]

## 153. DependencyStatus

- name: DependencyStatus
- source_file: mirage/production/schema.py
- bases: ["str", "Enum"]

## 154. ScopeContext

- name: ScopeContext
- source_file: mirage/production/schema.py
- bases: ["BaseModel"]

## 155. ResourceLimits

- name: ResourceLimits
- source_file: mirage/production/schema.py
- bases: ["BaseModel"]

## 156. BackupPolicy

- name: BackupPolicy
- source_file: mirage/production/schema.py
- bases: ["BaseModel"]

## 157. DeploymentProfileConfig

- name: DeploymentProfileConfig
- source_file: mirage/production/schema.py
- bases: ["BaseModel"]

## 158. AuthConfig

- name: AuthConfig
- source_file: mirage/production/schema.py
- bases: ["BaseModel"]

## 159. TLSConfig

- name: TLSConfig
- source_file: mirage/production/schema.py
- bases: ["BaseModel"]

## 160. StorageConfig

- name: StorageConfig
- source_file: mirage/production/schema.py
- bases: ["BaseModel"]

## 161. EventTransportConfig

- name: EventTransportConfig
- source_file: mirage/production/schema.py
- bases: ["BaseModel"]

## 162. ProductionAuditConfig

- name: ProductionAuditConfig
- source_file: mirage/production/schema.py
- bases: ["BaseModel"]

## 163. APIProtectionConfig

- name: APIProtectionConfig
- source_file: mirage/production/schema.py
- bases: ["BaseModel"]

## 164. ProductionConfig

- name: ProductionConfig
- source_file: mirage/production/schema.py
- bases: ["BaseModel"]

## 165. ValidationFinding

- name: ValidationFinding
- source_file: mirage/production/schema.py
- bases: ["BaseModel"]

## 166. ValidationReport

- name: ValidationReport
- source_file: mirage/production/schema.py
- bases: ["BaseModel"]

## 167. DependencyCheckResult

- name: DependencyCheckResult
- source_file: mirage/production/schema.py
- bases: ["BaseModel"]

## 168. HealthReport

- name: HealthReport
- source_file: mirage/production/schema.py
- bases: ["BaseModel"]

## 169. UserIdentity

- name: UserIdentity
- source_file: mirage/production/schema.py
- bases: ["BaseModel"]

## 170. ApprovalRecord

- name: ApprovalRecord
- source_file: mirage/production/schema.py
- bases: ["BaseModel"]

## 171. DeploymentLevelRecord

- name: DeploymentLevelRecord
- source_file: mirage/production/schema.py
- bases: ["BaseModel"]

## 172. SOCIncident

- name: SOCIncident
- source_file: mirage/production/soc.py
- bases: ["BaseModel"]

## 173. RecordEnvelope

- name: RecordEnvelope
- source_file: mirage/production/storage.py
- bases: ["BaseModel"]

## 174. StrictRLModel

- name: StrictRLModel
- source_file: mirage/rl/schema.py
- bases: ["BaseModel"]

## 175. BlueTeamTactic

- name: BlueTeamTactic
- source_file: mirage/rl/schema.py
- bases: ["str", "Enum"]

## 176. RLTrajectorySource

- name: RLTrajectorySource
- source_file: mirage/rl/schema.py
- bases: ["str", "Enum"]

## 177. RLDatasetSplit

- name: RLDatasetSplit
- source_file: mirage/rl/schema.py
- bases: ["str", "Enum"]

## 178. PolicyStatus

- name: PolicyStatus
- source_file: mirage/rl/schema.py
- bases: ["str", "Enum"]

## 179. RLOperatingMode

- name: RLOperatingMode
- source_file: mirage/rl/schema.py
- bases: ["str", "Enum"]

## 180. StrictVerificationModel

- name: StrictVerificationModel
- source_file: mirage/verification/schema.py
- bases: ["BaseModel"]

## 181. InvariantCategory

- name: InvariantCategory
- source_file: mirage/verification/schema.py
- bases: ["str", "Enum"]

## 182. VerificationSeverity

- name: VerificationSeverity
- source_file: mirage/verification/schema.py
- bases: ["str", "Enum"]

## 183. ViolationResponse

- name: ViolationResponse
- source_file: mirage/verification/schema.py
- bases: ["str", "Enum"]

## 184. VerificationResult

- name: VerificationResult
- source_file: mirage/verification/schema.py
- bases: ["str", "Enum"]

## 185. FormalVerificationVerdict

- name: FormalVerificationVerdict
- source_file: mirage/verification/schema.py
- bases: ["str", "Enum"]
