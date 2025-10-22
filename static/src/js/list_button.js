/** @odoo-module **/

import { registry } from "@web/core/registry";
import { useService } from "@web/core/utils/hooks";
import { listView } from "@web/views/list/list_view";
import { ListController } from "@web/views/list/list_controller";

export class ListItadmin extends ListController {
    setup() {
        super.setup();
        this.action = useService("action");
        // this.rpc = useService("rpc");
        // this.notification = useService("notification");
    }

    async _onClickImportarXML(event) {
        event.stopPropagation();
        await this.action.doAction({
            name: "Attach Files",
            type: "ir.actions.act_window",
            view_mode: "form",
            views: [[false, "form"]],
            target: "new",
            res_model: "multi.file.attach.xmls.wizard",
        });
    }

    async _onClickDescargaXDia(event) {
        event.stopPropagation();
        await this.action.doAction({
            name: "Descarga x Dia",
            type: "ir.actions.act_window",
            view_mode: "form",
            views: [[false, "form"]],
            target: "new",
            res_model: "descarga.x.dia.wizard",
        });
    }

    async _onImportFIELSatInvoice(event) {
        event.stopPropagation();
        // await this.rpc("/web/dataset/call_kw/res.company/import_current_company_invoice", {
        //     args: [],
        //     kwargs: {},
        // });
        // this.notification.add("Importación completada", { type: "success" });
    }

    async _onClickSincronizarDocumentos(event) {
        event.stopPropagation();
        // await this.rpc("/web/dataset/call_kw/ir.attachment/update_status_from_ir_attachment_document", {
        //     args: [],
        //     kwargs: {},
        // });
        // this.notification.add("Documentos sincronizados correctamente", { type: "success" });
    }
}

export const itadmin = {
    ...listView,
    Controller: ListItadmin,
    buttonTemplate: "l10n_mx_sat_sync_itadmin.ListView.Buttons",
};

registry.category("views").add("itadmin_tree", itadmin);
