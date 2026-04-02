import type { ConversionKey, ConversionOption } from "./helpers";

export function RecipeActionForm(props: {
  selectedKey: ConversionKey;
  selected: ConversionOption;
  options: ConversionOption[];
  loading: boolean;
  busy: string | null;
  missingPassword: boolean;
  requiresSourcePassword: boolean;
  requiresOutputPassword: boolean;
  sourcePassword: string;
  outputPassword: string;
  showSourcePassword: boolean;
  showOutputPassword: boolean;
  onChangeSelected: (value: ConversionKey) => void;
  onChangeSourcePassword: (value: string) => void;
  onChangeOutputPassword: (value: string) => void;
  onToggleSourcePassword: () => void;
  onToggleOutputPassword: () => void;
}) {
  const {
    selectedKey,
    selected,
    options,
    loading,
    busy,
    missingPassword,
    requiresSourcePassword,
    requiresOutputPassword,
    sourcePassword,
    outputPassword,
    showSourcePassword,
    showOutputPassword,
    onChangeSelected,
    onChangeSourcePassword,
    onChangeOutputPassword,
    onToggleSourcePassword,
    onToggleOutputPassword
  } = props;

  return (
    <div className="conversionPanel">
      <div className="conversionTopbar">
        <div className="conversionField">
          <label className="small">Tipo de conversao</label>
          <select
            className="input selectInput"
            value={selectedKey}
            onChange={(e) => onChangeSelected(e.target.value as ConversionKey)}
          >
            {options.map((option) => (
              <option key={option.key} value={option.key}>
                {option.label}
              </option>
            ))}
          </select>
        </div>

        <div className="conversionActions">
          <button
            className={selected.primary ? "btn primary" : "btn"}
            disabled={!selected.isEnabled || loading || missingPassword}
            onClick={() => selected.run()}
            type="button"
          >
            {busy ? "Processando..." : selected.buttonLabel}
          </button>
        </div>
      </div>

      <div className="conversionSummary">
        <div className="conversionSummaryRow">
          <span className="recipeLabel">Voce precisa de</span>
          <strong>{selected.requirements}</strong>
        </div>
        <div className="conversionSummaryRow">
          <span className="recipeLabel">Voce vai gerar</span>
          <strong>{selected.resultLabel}</strong>
        </div>
        {!selected.isEnabled ? (
          <div className="conversionSummaryRow">
            <span className="recipeLabel">Status</span>
            <strong>{selected.unavailableReason ?? "Essa conversao nao esta disponivel com os arquivos enviados."}</strong>
          </div>
        ) : selected.passwordHint ? (
          <div className="conversionSummaryRow">
            <span className="recipeLabel">Importante</span>
            <strong>{selected.passwordHint}</strong>
          </div>
        ) : null}
        {selected.isEnabled && selected.validationHint ? (
          <div className="conversionSummaryRow">
            <span className="recipeLabel">Validacao</span>
            <strong>{selected.validationHint}</strong>
          </div>
        ) : null}
        {selected.deploymentHint ? (
          <div className="conversionSummaryRow">
            <span className="recipeLabel">Uso no servidor</span>
            <strong>{selected.deploymentHint}</strong>
          </div>
        ) : null}
        {missingPassword ? (
          <div className="conversionSummaryRow">
            <span className="recipeLabel">Falta</span>
            <strong>
              {requiresSourcePassword && requiresOutputPassword
                ? "Informe a senha do arquivo enviado e a senha do novo arquivo."
                : requiresSourcePassword
                  ? "Informe a senha do arquivo enviado."
                  : "Informe a senha do novo arquivo."}
            </strong>
          </div>
        ) : null}
        {(requiresSourcePassword || requiresOutputPassword) ? (
          <div className="conversionMeta">
            <div className="metaChip">
              <span className="recipeLabel">Senha</span>
              <strong>
                {requiresSourcePassword && requiresOutputPassword
                  ? "Arquivo enviado e arquivo gerado"
                  : requiresSourcePassword
                    ? "Arquivo enviado"
                    : "Arquivo gerado"}
              </strong>
            </div>
          </div>
        ) : null}
      </div>

      {requiresSourcePassword ? (
        <div className="conversionField">
          <label className="small">Senha do arquivo enviado</label>
          <div className="row actionPasswordControls">
            <input
              className="input"
              type={showSourcePassword ? "text" : "password"}
              value={sourcePassword}
              onChange={(e) => onChangeSourcePassword(e.target.value)}
              placeholder="senha do PFX/P12"
              autoComplete="off"
              inputMode="text"
            />
            <button className="btn" type="button" onClick={onToggleSourcePassword}>
              {showSourcePassword ? "Ocultar" : "Mostrar"}
            </button>
          </div>
        </div>
      ) : null}

      {requiresOutputPassword ? (
        <div className="conversionField">
          <label className="small">Senha do novo arquivo</label>
          <div className="row actionPasswordControls">
            <input
              className="input"
              type={showOutputPassword ? "text" : "password"}
              value={outputPassword}
              onChange={(e) => onChangeOutputPassword(e.target.value)}
              placeholder="defina a senha"
              autoComplete="off"
              inputMode="text"
            />
            <button className="btn" type="button" onClick={onToggleOutputPassword}>
              {showOutputPassword ? "Ocultar" : "Mostrar"}
            </button>
          </div>
        </div>
      ) : null}
    </div>
  );
}
