var popup_hint_api = {
	"is_outdoor_location": function(value){
		return ["Outdoor", "Yard", "Balcony"].indexOf(value) != -1;
	},
	"get_outdoor_inactive_text": function(){
		return `<span style='color:#FC0'><#Outdoor_desc_title#></span>
			<ol>
				<li><#Outdoor_inactive_desc_1#></li>
				<li><#Outdoor_inactive_desc_2#></li>
			</ol>`;
	},
	"get_outdoor_active_text": function(){
		return `<span style='color:#FC0'><#Outdoor_desc_title#></span>
			<ol>
				<li><#Outdoor_active_desc_1#></li>
				<li><#Outdoor_active_desc_2#></li>
				<li><#Outdoor_active_desc_3#></li>
				<li><span style='color:#FC0'><#Outdoor_active_desc_4#></span></li>
			</ol>`;
	},
	"get_component_title": function(){
		return $("<div>").addClass("hint_title");
	},
	"get_component_text": function(){
		return $("<div>").addClass("hint_text");
	},
	"get_component_action": function(){
		var $action_bg = $("<div>").addClass("action_bg");
		var $action_canacl = $("<input/>").attr({"id":"action_canacl", "type":"button", "value":"<#CTL_Cancel#>"}).addClass("button_gen");
		var $action_ok = $("<input/>").attr({"id":"action_ok", "type":"button", "value":"<#CTL_ok#>"}).addClass("button_gen");
		$action_bg.append($action_canacl).append($action_ok);
		return $action_bg;
	},
	"get_component_loading": function(){
		var loadContainer = $("<div>").addClass("cssload-bell");
		for(var i=0; i<5; i++){
			$("<div>")
				.addClass("cssload-circle")
				.append($("<div>").addClass("cssload-inner"))
				.appendTo(loadContainer);
		}
		return $("<div>").addClass("cssload-bellContainer").append(loadContainer);
	},
	"get_component_mask": function(){
		return $("<div>").addClass("mask_bg");
	}
};
