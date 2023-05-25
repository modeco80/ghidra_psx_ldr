package ghidra.app.plugin.core.decompile.actions;

import java.awt.event.InputEvent;
import java.awt.event.KeyEvent;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import docking.action.KeyBindingData;
import docking.action.MenuData;
import ghidra.app.decompiler.ClangFieldToken;
import ghidra.app.decompiler.ClangFuncNameToken;
import ghidra.app.decompiler.ClangReturnType;
import ghidra.app.decompiler.ClangToken;
import ghidra.app.decompiler.ClangVariableToken;
import ghidra.app.plugin.core.decompile.DecompilerActionContext;
import ghidra.app.plugin.core.decompile.DecompilerProvider;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.LocalSymbolMap;
import ghidra.program.model.pcode.GlobalSymbolMap;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighVariable;

import ghidra.program.model.pcode.HighFunctionDBUtil;
import ghidra.util.UndefinedFunction;
import ghidra.util.task.TaskLauncher;
import psx.PsxAnalyzer;
import psx.PsxPlugin;
import psx.PsxUpdateAddressSpacesOverride;
import psx.PsxUpdateAddressSpacesTask;

public class PsxUpdateAddressSpacesAction extends AbstractDecompilerAction {
	
	private static final String NAME = "Update Symbol Address Space";
	
	public PsxUpdateAddressSpacesAction() {
		super(NAME);
		
		setKeyBindingData(new KeyBindingData(KeyEvent.VK_O, InputEvent.CTRL_DOWN_MASK));
		setPopupMenuData(new MenuData(new String[] { NAME }, "Decompiler"));
	}
	
	private boolean isFunctionCall(ClangToken tokenAtCursor) {
		return (tokenAtCursor instanceof ClangFuncNameToken);
	}

	/**
	 * Find the HighSymbol the decompiler associates with a specific address.
	 * @param addr is the specific address
	 * @param highFunction is the decompiler results in which to search for the symbol
	 * @return the matching symbol or null if no symbol exists
	 */
	private static HighSymbol findHighSymbol(Address addr, HighFunction highFunction) {
		HighSymbol highSymbol = null;
		if (addr.isStackAddress()) {
			LocalSymbolMap lsym = highFunction.getLocalSymbolMap();
			highSymbol = lsym.findLocal(addr, null);
		}
		else {
			GlobalSymbolMap gsym = highFunction.getGlobalSymbolMap();
			highSymbol = gsym.getSymbol(addr);
		}
		return highSymbol;
	}

	/**
	 * Track down the HighSymbol associated with a particular token.  The token may be directly attached to
	 * the symbol, or it may be a reference that needs to be looked up.
	 * @param token is the given token
	 * @param highFunction is the decompiler model of the function
	 * @return the associated HighSymbol or null if one can't be found
	 */
	public static HighSymbol findHighSymbolFromToken(ClangToken token, HighFunction highFunction) {
		if (highFunction == null) {
			return null;
		}
		HighVariable variable = token.getHighVariable();
		HighSymbol highSymbol = null;
		if (variable == null) {
			// Token may be from a variable reference, in which case we have to dig to find the actual symbol
			Function function = highFunction.getFunction();
			if (function == null) {
				return null;
			}
			Address storageAddress = getStorageAddress(token, function.getProgram());
			if (storageAddress == null) {
				return null;
			}
			highSymbol = findHighSymbol(storageAddress, highFunction);
		}
		else {
			highSymbol = variable.getSymbol();
		}
		return highSymbol;
	}

	/**
	 * Get the storage address of the variable attached to the given token, if any.
	 * The variable may be directly referenced by the token, or indirectly referenced as a point.
	 * @param tokenAtCursor is the given token
	 * @param program is the Program
	 * @return the storage Address or null if there is no variable attached
	 */
	private static Address getStorageAddress(ClangToken tokenAtCursor, Program program) {
		Varnode vnode = tokenAtCursor.getVarnode();
		Address storageAddress = null;
		if (vnode != null) {
			storageAddress = vnode.getAddress();
		}
		// op could be a PTRSUB, need to dig it out...
		else if (tokenAtCursor instanceof ClangVariableToken) {
			PcodeOp op = ((ClangVariableToken) tokenAtCursor).getPcodeOp();
			storageAddress = HighFunctionDBUtil.getSpacebaseReferenceAddress(program.getAddressFactory(), op);
		}
		return storageAddress;
	}


	@Override
	protected boolean isEnabledForDecompilerContext(DecompilerActionContext context) {
		if (!PsxAnalyzer.isPsxLoaderOrPsxLanguage(context.getProgram())) {
			return false;
		}
		
		Function function = context.getFunction();
		if (function == null || function instanceof UndefinedFunction) {
			return false;
		}

		ClangToken tokenAtCursor = context.getTokenAtCursor();
		if (tokenAtCursor == null) {
			return false;
		}
		if (tokenAtCursor instanceof ClangFieldToken) {
			return false;
		}
		if (tokenAtCursor.Parent() instanceof ClangReturnType) {
			return false;
		}

		HighSymbol highSymbol = findHighSymbolFromToken(tokenAtCursor, context.getHighFunction());
		if (highSymbol == null) {
			return isFunctionCall(tokenAtCursor);
		}
		return highSymbol.isGlobal();
	}

	@Override
	protected void decompilerActionPerformed(DecompilerActionContext context) {
		PluginTool tool = context.getTool();
		
		Function func = context.getFunction();
		
		DecompilerProvider decompProvider = context.getComponentProvider();
		
		PsxPlugin psxPlugin = PsxPlugin.getPsxPlugin(tool);
		
		List<PsxUpdateAddressSpacesOverride> newMap = new ArrayList<>();
		
		Map<Address, String> entries = PsxPlugin.collectFunctionOverlayedEntries(decompProvider, func);
		PsxUpdateAddressSpacesTask task = new PsxUpdateAddressSpacesTask(psxPlugin, decompProvider, newMap, entries, context.getTokenAtCursor());
		new TaskLauncher(task, tool.getToolFrame());
		
		psxPlugin.mergeOverrides(newMap);
	}

}
