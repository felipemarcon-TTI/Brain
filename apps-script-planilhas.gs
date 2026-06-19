/**
 * ViennaPet — Web App para registrar Cupons e Afiliados nas planilhas.
 *
 * COMO PUBLICAR:
 * 1. Abra https://script.google.com  >  Novo projeto
 * 2. Cole TODO este conteúdo (apague o que vier por padrão)
 * 3. Troque o valor de SECRET abaixo por um segredo forte (qualquer string longa)
 * 4. Implantar > Nova implantação > Tipo: "App da Web"
 *      - Executar como: Eu (sua conta)
 *      - Quem tem acesso: Qualquer pessoa
 * 5. Copie a URL que termina em /exec
 * 6. No Railway (ViennaPet MCP) adicione:
 *      SHEETS_WEBHOOK_URL = <a URL /exec>
 *      SHEETS_SECRET      = <o mesmo SECRET deste script>
 *
 * As planilhas já existem (IDs abaixo). O script roda na SUA conta, então não
 * precisa de chave de service account nem compartilhamento extra.
 */

const SECRET = "TROQUE-POR-UM-SEGREDO-FORTE";

const CUPONS_ID    = "1RBzTk8hG-bZCfOYnxFFuENifKaGEycMYBVCmLity2bw";
const AFILIADOS_ID = "1XTRoCdnBjZ2ZZw6ixCuVuBDIOilTTrjW18-F8aDLHfM";

function doPost(e) {
  try {
    const b = JSON.parse(e.postData.contents);
    if (b.secret !== SECRET) return json({ ok: false, error: "unauthorized" });

    if (b.action === "ping") return json({ ok: true });

    if (b.action === "append_cupom") {
      const sh = SpreadsheetApp.openById(CUPONS_ID).getSheets()[0];
      sh.appendRow([b.codigo, b.validade, b.desconto, b.dono, b.obs || ""]);
      return json({ ok: true });
    }

    if (b.action === "append_afiliado") {
      const sh = SpreadsheetApp.openById(AFILIADOS_ID).getSheets()[0];
      sh.appendRow([b.arroba, b.url]);
      return json({ ok: true });
    }

    if (b.action === "revoke_cupom") {
      const sh = SpreadsheetApp.openById(CUPONS_ID).getSheets()[0];
      const data = sh.getDataRange().getValues();
      for (let i = 1; i < data.length; i++) {
        if (String(data[i][0]).trim() === String(b.codigo).trim()) {
          sh.getRange(i + 1, 2).setValue(b.validade); // B = Validade
          sh.getRange(i + 1, 5).setValue(b.obs);      // E = Observação
          return json({ ok: true, found: true });
        }
      }
      return json({ ok: true, found: false });
    }

    return json({ ok: false, error: "unknown action" });
  } catch (err) {
    return json({ ok: false, error: String(err) });
  }
}

function json(o) {
  return ContentService.createTextOutput(JSON.stringify(o))
    .setMimeType(ContentService.MimeType.JSON);
}
