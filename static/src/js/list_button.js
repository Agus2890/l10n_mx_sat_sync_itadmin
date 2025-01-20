/** @odoo-module **/


import { ListController } from '@web/views/list/list_controller';
import { listView } from '@web/views/list/list_view';
import { registry } from "@web/core/registry";

export class ListItadmin extends ListController {   

    async _onClickImportarXML (event) {
        debugger;
        event.stopPropagation();
        var self = this;
        return this.model.action.doAction({
            name: "Attach Files",
            type: 'ir.actions.act_window',
            view_mode: 'form',
            views: [[false, 'form']],
            target: 'new',
            res_model: 'multi.file.attach.xmls.wizard'
        });

    }

    async onClickDescargaXDia (event) {
        var self = this;

        return this.model.action.doAction({
            name: "Descarga x Dia",
            type: 'ir.actions.act_window',
            view_mode: 'form',
            views: [[false, 'form']],
            target: 'new',
            res_model: 'descarga.x.dia.wizard'
        });
    }

    async _onClickSincronizarDocumentos(event) {
       var self = this;
       await this.model.orm.call('ir.attachment','update_status_from_ir_attachment_document',[],{});
    }

    async _onImportFIELSatInvoice (event) {
        var self = this;
        await this.model.orm.call('res.company','import_current_company_invoice',[],{});
    }

    async _onClickImportarXML (event) {
        var self = this;
        return this.model.action.doAction({
            name: "Attach Files",
            type: 'ir.actions.act_window',
            view_mode: 'form',
            views: [[false, 'form']],
            target: 'new',
            res_model: 'multi.file.attach.xmls.wizard'
        });

    }




}

export const itadmin = {
    ...listView,
    Controller: ListItadmin,
    buttonTemplate: "l10n_mx_sat_sync_itadmin.ListView.Buttons",
};
registry.category("views").add("itadmin_tree", itadmin);