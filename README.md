Configuration Manual


1	Introduction 

This configuration manual provides the instructions required to configure, execute and reproduce the experimental environment developed for the explainable context aware DevSecOps vulnerability prioritisation framework.

The purpose of this manual is to allow an independent evaluator to recreate the project environment and execute the framework and machine learning experiments used within the research.

The project was implemented primarily in Python and consists of two principal components. The first is a deterministic context aware prioritisation framework that processes security findings, enriches them with organisational context, performs STRIDE based threat assessment and generates risk scores, P1-P4 priorities, explanations and remediation recommendations. 

The second is an experimental machine learning pipeline containing Decision Tree and Random Forest classifiers together with SHAP-based explainability.
The project also contains an external validation experiment using a frozen sample of 100 real world CVEs and independent exploitation indicators including CISA Known Exploited Vulnerabilities (KEV) status and EPSS.

2	Installation 

2.1	Extract the Project:
Extract
Devsecops-thesis-framework
Open Terminal and Navigate to the extracted directory
Cd/path/to/devsecops-thesis-framework
Confirm that the correct Directory has been opened 
Pwd
ls
The src, data and external_validation directories should be visible

3	Create the virtual Environment 
Create Isolated python Environment
Python3 -m venv .venv
MacOS/Linux: Activate Using 
source .venv/bin/activate
Windows PowerShell Using 
.venv\Scripts\Activate
4	Install dependencies 
1.	Python3 -m pip install –upgrade pip
2.	Python3 -m pip install -r requirements.txt
3.	python3 -c "import pandas, numpy, sklearn, scipy, shap, joblib, requests, streamlit; print('Environment configured successfully')"
5	Install dependencies 
The project contains  a .env configuration used by the Github and OpenAI components. The expected outputs are:
GITHUB_TOKEN=
GITHUB_OWNER=
GITHUB_REPO=
OPENAI_API_KEY=
The evaluator should insert their own credentials if they intend to retrieve new GitHub Dependabot alerts or execute the OpenAI-based functionality.
6. Running the Framework
6.1. Normalising Github Dependabot Findings
Run: Python3 src/analysis/normaliseevents.py
Input: data/dependabot_alerts_raw.json
Output/normalised_events.json

The script converts heterogeneous Dependabot attributes into the common internal event representation used by the framework.

6.2 Risk Enrichment and Prioritisation
Run: python3 src/analysis/riskenrichment.py
The Script will read:
Data/all_normalised_events.json
Data/asset_context.json
Data/asset_context_rules.json
And generates:
data/enriched_events.json

The enrichment stage performs contextual assessment, STRIDE mapping, deterministic risk scoring, priority assignment and recommendation generation.
Each processed event contains information including its risk score, P1–P4 priority, contextual characteristics and explanation.
7. Dashboard
The project includes a Streamlit dashboard for viewing enriched security events.
After generating data/enriched_events.json, start the dashboard using:
Run: streamlit run src/dashboard/dashboard.py

Streamlit should display a local address in the terminal. Open this address in a web browser.
The dashboard provides filtering and inspection of the enriched findings, including their severity and assigned priority.

Terminal the dashboard using:
Run: Ctrl + c

8. Machine Learning experiments
8.1 Generate the Experimental Dataset
Run: python3 src/ml/generate_training_dataset_v2.py
Input: data/all_normalised_events.json
Output:data/ml/ml_training_dataset_v2.json
8.2 Build the Machine Learning Feature Dataset
Run:python3 src/ml/build_ml_dataset_v2.py
Input:
data/ml/ml_training_dataset_v2.json
Output:
data/ml/ml_training_features_v2.csv
This converts the enriched events into the structured feature representation required by the supervised learning models.

8.3 Create Training and Testing Sets
Run:python3 src/ml/prepare_ml_split_v2.py

The script uses a group aware splitting procedure to reduce leakage between related security events.
The configured test size is:
22%
with the split beginning from:
random_state = 42
Outputs:
data/ml/ml_train_v2.csv
data/ml/ml_test_v2.csv
The final experimental split contains:
3,848 training events
1,152 testing events

8.4 Label Independence Audit
The project contains an additional audit designed to examine the training and testing data for potential label leakage or identifier-related issues.
Run:python3 src/ml/audit_label_independence_v2.py
This should be executed after creating ml_train_v2.csv and ml_test_v2.csv.

9. Decision Tree Experiment
Train and evaluate the Decision Tree using:
Run:python3 src/ml/train_decisiontree_v2.py
The script reads:
data/ml/ml_train_v2.csv
data/ml/ml_test_v2.csv
and excludes event identifiers from the predictive features.
Generated outputs are stored under:
data/ml/ml_results/
including:
decision_tree_model_v2.joblib
decision_tree_results_v2.json
The dissertation experiment produced approximately:
Accuracy: 96.79%
Precision: 98.06%
Recall: 96.01%
F1 Score: 96.83%
The confusion matrix should show the 37 observed errors concentrated between P3 and P4, with P1 and P2 correctly classified in the reported experiment.
10. Random Forest Experiment
Run:python3 src/ml/train_randomforest_v2.py

The script uses the same training and testing datasets as the Decision Tree.
Outputs include:
data/ml/ml_results/random_forest_model_v2.joblib
data/ml/ml_results/random_forest_results_v2.json
The reported evaluation produced:
Accuracy: 96.79%
Precision: 98.06%
Recall: 96.01%
F1 Score: 96.83%

Using identical input data for both classifiers enables direct comparison between the Decision Tree and Random Forest.

11. SEVERITY AND CONTEXT AWARE PRIORITISATION COMPARISON
The project contains a dedicated experiment comparing different prioritisation feature sets.
Run: python3 src/evaluation/compare_prioritisation_models.py
The experiment compares:
Severity-only prioritisation
Context aware prioritisation
Combined technical and contextual prioritisation
The script uses a Random Forest with:
n_estimators = 300
random_state = 42
class_weight = balanced
The experiment generates comparison outputs including:
prioritisation_model_comparison.csv
prioritisation_model_improvements.csv
severity_only_confusion_matrix.csv
context_aware_confusion_matrix.csv
combined_confusion_matrix.csv
These files support the feature comparison results reported within the dissertation.

12. FEATURE ABLATION
To evaluate the contribution of individual feature groups, 
Run :python3 src/ml/evaluate_feature_ablation_v2.py
The script uses the same V2 training and testing datasets.
This experiment assesses how removing different technical or contextual features affects predictive performance and therefore helps evaluate whether organisational context contributes meaningful information to prioritisation.

13. SHAP explanability
The Random Forest model must be trained before executing the SHAP experiment.
Run: python3 src/ml/explain_randomforest_v2.py
The script loads:
data/ml/ml_results/random_forest_model_v2.joblib
data/ml/ml_test_v2.csv
SHAP explanations are generated for a maximum of:
100 test events
and the results are stored as:
data/ml/ml_results/random_forest_shap_v2.json
The output identifies the features contributing most strongly to individual Random Forest predictions.
The machine learning/XAI comparison can then be executed using:
python3 src/ml/compare_ml_xai_v2.py
which generates:
data/ml/ml_results/ml_xai_comparison_v2.json

14. Explainability Evaluation
The deterministic explanations generated by the framework can also be evaluated separately.
Run:python3 src/evaluation/evaluate_explainability.py
Input:
data/enriched_events.json
Output:
data/explainability_metrics.json
This evaluates the explanation information produced by the deterministic framework independently of SHAP.

15. Scalability Evaluation
The framework includes an experiment measuring processing performance across increasing workloads.
Run: python3 src/evaluation/evaluate_scalability.py
The experiment uses workload multipliers of:
1
10
50
100
500
Using the 18 base events, these correspond to:
18
180
900
1,800
9,000 events
Each workload is repeated five times following one warm-up run.
Results are saved to:
data/scalability_metrics.json
data/scalability_metrics.csv
The outputs contain the performance measurements used for the scalability evaluation.

16. External Real World CVE Validation
The project contains a separate external validation directory:
external_validation/
The experiment uses a frozen sample of 100 real world CVEs, containing:
50 CISA KEV vulnerabilities
50 non KEV vulnerabilities
The supplied frozen data should be used when reproducing the dissertation rather than downloading current NVD, CISA or EPSS datasets.
This is important because these external sources can change after the original experiment.
16.1 Build the Frozen Validation Sample
The original sample can be regenerated using:
Run: python3 src/evaluation/build_external_validation_sample.py
The configured random state is:
42
The generated sample is:
external_validation/processed/external_validation_sample_100.csv
For strict dissertation reproduction, however, the supplied frozen CSV should be retained.
16.2 Prepare Framework Compatible Events
Run:python3 src/evaluation/prepare_external_validation.py
Input:
external_validation/processed/external_validation_sample_100.csv
Output:
external_validation/processed/external_validation_events.json
This transforms the external CVEs into the event representation expected by the prioritisation framework.
16.3 Run the Framework Against the External CVEs
Run:python3 src/evaluation/run_external_validation.py
The experiment applies the same controlled organisational context to every CVE:
Environment: Production
Internet Facing: False
Runtime Reachable: True
Business Criticality: Medium
Data Sensitivity: Medium
Keeping context constant prevents arbitrary organisational characteristics from influencing the comparison between CVEs.
The results are written to:
external_validation/results/external_validation_framework_results.json

17. Evaluate External Validation Results
Run:python3 src/evaluation/evaluate_external_validation.py
This processes the framework output and generates the external validation analysis.
The base framework should produce the following priority distribution for the frozen 100-CVE sample:
P1: 3
P2: 64
P3: 32
P4: 1
The reported CISA KEV comparison is:
CISA KEV:
P1/P2 = 45
P3/P4 = 5
High-Priority Rate = 90%
Non-KEV:
P1/P2 = 22
P3/P4 = 28
High Priority Rate = 44%

18. Statistical External Validation
Run:python3 src/evaluation/statistical_external_validation.py
The script requires exactly 100 external validation results and performs statistical analysis using:
Fisher's exact test
Spearman rank correlation
The analysis evaluates the relationship between framework prioritisation, CISA KEV status and EPSS exploitation probability.
Generated outputs include:
external_validation/results/external_validation_statistical_data.csv
external_validation/results/external_validation_statistical_summary.json
For the submitted experiment, Spearman analysis identified a moderate statistically significant negative association between priority number and EPSS:
ρ = -0.496
p < .001
Because P1 represents the greatest urgency and P4 the lowest, the negative relationship indicates that higher exploitation probabilities tended to correspond with more urgent framework priorities.

19. Recommended Complete production sequence
For complete reproduction of the final experiments, execute the following from the project root in this order:
python3 src/analysis/normaliseevents.py
python3 src/analysis/riskenrichment.py
python3 src/ml/generate_training_dataset_v2.py
python3 src/ml/build_ml_dataset_v2.py
python3 src/ml/prepare_ml_split_v2.py
python3 src/ml/audit_label_independence_v2.py
python3 src/ml/train_decisiontree_v2.py
python3 src/ml/train_randomforest_v2.py
python3 src/evaluation/compare_prioritisation_models.py
python3 src/ml/evaluate_feature_ablation_v2.py
python3 src/ml/explain_randomforest_v2.py
python3 src/ml/compare_ml_xai_v2.py
python3 src/evaluation/evaluate_explainability.py
python3 src/evaluation/evaluate_scalability.py
python3 src/evaluation/prepare_external_validation.py
python3 src/evaluation/run_external_validation.py
python3 src/evaluation/evaluate_external_validation.py
python3 src/evaluation/statistical_external_validation.py
The external validation sample does not need to be rebuilt when reproducing the final experiment because the frozen sample is already supplied.

20. Optional Github Data Collection 
The supplied frozen dataset is sufficient to reproduce the dissertation. However, new GitHub Dependabot findings can optionally be retrieved.
Configure the following variables inside .env:
GITHUB_TOKEN
GITHUB_OWNER
GITHUB_REPO
Run: python3 src/github/fetch_dependabot_alerts.py
The resulting alerts are saved to:
data/dependabot_alerts_raw.json
These can subsequently be normalised using:
Run: python3 src/analysis/normaliseevents.py
Newly retrieved data should not be expected to reproduce the dissertation results exactly because the repository's Dependabot findings may have changed.

21. Optional OpenAI Component
The project contains optional AI functionality under:
src/AI/
including:
aipromptgenerator.py
openaianalyser.py
Use of this component requires:
OPENAI_API_KEY
within the .env file.
This functionality is not required for reproducing the core deterministic prioritisation, Decision Tree, Random Forest, SHAP or external validation experiments.

22. Troubleshoot
If Python reports that a module cannot be found, confirm that the virtual environment is active and reinstall the dependencies:
Run: python3 -m pip install -r requirements.txt
If a script reports that a dataset cannot be found, ensure the command is being executed from:
devsecops-thesis-framework/
rather than from inside src/.
Check the current location using:
pwd
and inspect the files using:
ls
If the Random Forest SHAP script reports that the model cannot be found, first execute:
python3 src/ml/train_randomforest_v2.py
before:
python3 src/ml/explain_randomforest_v2.py
If external validation fails because the framework results do not exist, execute:
python3 src/evaluation/prepare_external_validation.py
python3 src/evaluation/run_external_validation.py
before running the evaluation or statistical scripts.
If reproduced machine learning results differ, verify that the following remain unchanged:
- Supplied input datasets
- Random seed/state
- Group aware train/test split
- Preprocessing procedure
- Feature set
- Classifier parameters
- Python version
- Dependency versions

23. Reproducibility notes 
The project includes both frozen experimental data and scripts capable of generating or processing new data. The frozen datasets should be used when verifying the dissertation results.
Downloading new vulnerability information or collecting new Dependabot findings can result in different outputs because vulnerability databases, exploitation information and repository findings evolve over time.
Similarly, the external validation sample should remain unchanged when reproducing the reported experiment.
The V2 machine learning scripts should be treated as the final experimental implementation:
generate_training_dataset_v2.py
build_ml_dataset_v2.py
prepare_ml_split_v2.py
train_decisiontree_v2.py
train_randomforest_v2.py
evaluate_feature_ablation_v2.py
explain_randomforest_v2.py
compare_ml_xai_v2.py
Earlier non-V2 scripts remain within the project as development artefacts but are not required for reproducing the final machine learning results.

24. Successful project completion. 
The project environment can be considered successfully configured when:
1. Python dependencies install without errors.
2. riskenrichment.py successfully generates data/enriched_events.json.
3. The Decision Tree and Random Forest models train and evaluate successfully.
4. The machine learning evaluation reproduces approximately the performance reported within the dissertation.
5. SHAP explanations are successfully generated.
6. The explainability and scalability evaluations execute successfully.
7. The frozen 100 CVE external validation experiment completes successfully.
8. The generated results correspond with the experimental results reported within the dissertation.

Successful completion of these stages confirms that the deterministic context-aware framework, machine learning evaluation and external real world validation environment have been reproduced.















