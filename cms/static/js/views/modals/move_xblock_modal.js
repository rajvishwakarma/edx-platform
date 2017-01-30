/**
 * The MoveXblockModal to move XBlocks in course.
 */
define([
    'jquery', 'backbone', 'underscore', 'gettext',
    'js/views/baseview', 'js/views/modals/base_modal',
    'js/models/xblock_info', 'js/views/move_xblock_list', 'js/views/move_xblock_breadcrumb',
    'common/js/components/views/feedback',
    'js/views/utils/xblock_utils',
    'js/views/utils/move_xblock_utils',
    'edx-ui-toolkit/js/utils/html-utils',
    'edx-ui-toolkit/js/utils/string-utils',
    'text!templates/move-xblock-modal.underscore'
],
function($, Backbone, _, gettext, BaseView, BaseModal, XBlockInfoModel, MoveXBlockListView, MoveXBlockBreadcrumbView,
         Feedback, XBlockViewUtils, MoveXBlockUtils, HtmlUtils, StringUtils, MoveXblockModalTemplate) {
    'use strict';

    var MoveXblockModal = BaseModal.extend({
        modalSRTitle: gettext('Choose a location to move your component to'),

        events: _.extend({}, BaseModal.prototype.events, {
            'click .action-move': 'moveXBlock'
        }),

        options: $.extend({}, BaseModal.prototype.options, {
            modalName: 'move-xblock',
            modalSize: 'ml',
            addPrimaryActionButton: true,
            primaryActionButtonType: 'move',
            viewSpecificClasses: 'move-modal',
            primaryActionButtonTitle: gettext('Move'),
            modalSRTitle: gettext('Choose a location to move your component to')
        }),

        initialize: function() {
            BaseModal.prototype.initialize.call(this);
            this.listenTo(Backbone, 'move:breadcrumbRendered', this.focusModal);
            this.sourceXBlockInfo = this.options.sourceXBlockInfo;
            this.sourceParentXBlockInfo = this.options.sourceParentXBlockInfo;
            this.targetParentXBlockInfo = null;
            this.XBlockUrlRoot = this.options.XBlockUrlRoot;
            this.XBlockAncestorInfoUrl = StringUtils.interpolate(
                '{urlRoot}/{usageId}?fields=ancestorInfo',
                {urlRoot: this.XBlockUrlRoot, usageId: this.sourceXBlockInfo.get('id')}
            );
            this.outlineURL = this.options.outlineURL;
            this.options.title = this.getTitle();
            this.movedAlertView = null;
            this.moveXBlockBreadcrumbView = null;
            this.moveXBlockListView = null;
            this.isValidMove  = false;
            this.fetchCourseOutline();
            this.listenTo(Backbone, 'move:enableMoveOperation', this.enableMoveOperation);
        },

        getTitle: function() {
            return StringUtils.interpolate(
                gettext('Move: {displayName}'),
                {displayName: this.sourceXBlockInfo.get('display_name')}
            );
        },

        getContentHtml: function() {
            return _.template(MoveXblockModalTemplate)({});
        },

        show: function() {
            BaseModal.prototype.show.apply(this, [false]);
            Feedback.prototype.inFocus.apply(this, [this.options.modalWindowClass]);
            this.updateMoveState(false);
            MoveXBlockUtils.hideMovedNotification(Feedback);
        },

        hide: function() {
            if (this.moveXBlockListView) {
                this.moveXBlockListView.remove();
            }
            if (this.moveXBlockBreadcrumbView) {
                this.moveXBlockBreadcrumbView.remove();
            }
            BaseModal.prototype.hide.apply(this);
            Feedback.prototype.outFocus.apply(this);
        },

        focusModal: function() {
            Feedback.prototype.inFocus.apply(this, [this.options.modalWindowClass]);
        },

        fetchCourseOutline: function() {
            var self = this;
            $.when(
                $.ajax({
                    url: this.outlineURL,
                    contentType: 'application/json',
                    dataType: 'json',
                    type: 'GET'
                }),
                $.ajax({
                    url: this.XBlockAncestorInfoUrl,
                    contentType: 'application/json',
                    dataType: 'json',
                    type: 'GET'
                })
            ).then(function(outlineResponse, ancestorResponse) {
                $('.ui-loading').addClass('is-hidden');
                $('.breadcrumb-container').removeClass('is-hidden');
                self.renderViews(outlineResponse[0], ancestorResponse[0]);
            });
        },

        renderViews: function(outlineJson, ancestorInfo) {
            this.moveXBlockBreadcrumbView = new MoveXBlockBreadcrumbView({});
            this.moveXBlockListView = new MoveXBlockListView(
                {
                    model: new XBlockInfoModel(outlineJson, {parse: true}),
                    ancestorInfo: ancestorInfo
                }
            );
        },

        updateMoveState: function(isValidMove) {
            var $moveButton = this.$el.find('.action-move');
            if (isValidMove) {
                $moveButton.removeClass('is-disabled');
            } else {
                $moveButton.addClass('is-disabled');
            }
            this.isValidMove = isValidMove || false;
        },

        enableMoveOperation: function(targetParentXBlockInfo) {
            var isValidMove = false,
                sourceParentType = this.sourceParentXBlockInfo.get('category'),
                targetParentType = targetParentXBlockInfo.get('category');

            if (targetParentType === sourceParentType && this.sourceParentXBlockInfo.id !== targetParentXBlockInfo.id) {
                isValidMove = true;
                this.targetParentXBlockInfo = targetParentXBlockInfo;
            }
            this.updateMoveState(isValidMove);
        },

        moveXBlock: function() {
            var self = this;
            if (!self.isValidMove) {
                return;
            }

            XBlockViewUtils.moveXBlock(self.sourceXBlockInfo.id, self.targetParentXBlockInfo.id)
                .done(function(response) {
                    if (response.move_source_locator) {
                        // hide modal
                        self.hide();
                        // hide xblock element
                        $("li.studio-xblock-wrapper[data-locator='" + self.sourceXBlockInfo.id + "']").hide();
                        self.movedAlertView = MoveXBlockUtils.showMovedNotification(
                            StringUtils.interpolate(
                                gettext('Success! "{displayName}" has been moved.'),
                                {
                                    displayName: self.sourceXBlockInfo.get('display_name')
                                }
                            ),
                            StringUtils.interpolate(
                                gettext('{link_start}Take me to the new location{link_end}'),
                                {
                                    link_start: HtmlUtils.HTML('<a href="/container/' + response.parent_locator + '">'),
                                    link_end: HtmlUtils.HTML('</a>')
                                }
                            ),
                            HtmlUtils.interpolateHtml(
                                HtmlUtils.HTML(
                                    '<a class="action-undo-move" href="#" data-source-display-name="{displayName}" ' +
                                    'data-source-locator="{sourceLocator}" ' +
                                    'data-source-parent-locator="{sourceParentLocator}" ' +
                                    'data-target-index="{targetIndex}">{undoMove}</a>'
                                ),
                                {
                                    displayName: self.sourceXBlockInfo.get('display_name'),
                                    sourceLocator: self.sourceXBlockInfo.id,
                                    sourceParentLocator: self.sourceParentXBlockInfo.id,
                                    targetIndex: response.source_index,
                                    undoMove: gettext('Undo move')
                                }
                            )
                        );
                    }
                });
        }
    });

    return MoveXblockModal;
});
